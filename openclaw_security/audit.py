from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import SecurityDecision

DEFAULT_STATS = {
    "events": 0,
    "allowed": 0,
    "warned": 0,
    "blocked": 0,
    "cache_hits": 0,
    "avg_ti_latency_ms": 0.0,
}


class AuditTrail:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.state_dir = self.base_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.state_dir / "audit.jsonl"
        self.stats_path = self.state_dir / "stats.json"
        if not self.stats_path.exists():
            self._save_stats(DEFAULT_STATS.copy())

    def _load_stats(self) -> dict[str, Any]:
        if not self.stats_path.exists():
            return DEFAULT_STATS.copy()
        try:
            loaded = json.loads(self.stats_path.read_text(encoding="utf-8"))
            return {**DEFAULT_STATS, **loaded}
        except json.JSONDecodeError:
            return DEFAULT_STATS.copy()

    def _save_stats(self, stats: dict[str, Any]) -> None:
        self.stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    def record_cache_hit(self) -> None:
        stats = self._load_stats()
        stats["cache_hits"] += 1
        self._save_stats(stats)

    def log_event(self, event: dict[str, Any], decision: SecurityDecision) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event.get("event_type", "unknown"),
            "target": event.get("target") or event.get("url") or event.get("path") or "",
            "intent": event.get("intent", ""),
            "status": decision.status,
            "action": decision.action,
            "summary": decision.summary,
            "findings": [finding.to_dict() for finding in decision.findings],
            "ti_results": [result.to_dict() for result in decision.ti_results],
        }

        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

        stats = self._load_stats()
        stats["events"] += 1
        if decision.status == "blocked":
            stats["blocked"] += 1
        elif decision.status == "warned":
            stats["warned"] += 1
        else:
            stats["allowed"] += 1

        latencies = [result.latency_ms for result in decision.ti_results if result.latency_ms]
        if latencies:
            previous_total = max(stats["events"] - 1, 0)
            current_total = sum(latencies) / len(latencies)
            stats["avg_ti_latency_ms"] = round(
                ((stats["avg_ti_latency_ms"] * previous_total) + current_total) / max(stats["events"], 1),
                2,
            )

        self._save_stats(stats)

    def read_logs(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        selected = lines[-limit:] if limit > 0 else lines
        entries: list[dict[str, Any]] = []
        for line in reversed(selected):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def clear_logs(self) -> int:
        count = len(self.read_logs(limit=1000000))
        self.audit_path.write_text("", encoding="utf-8")
        return count

    def get_stats(self) -> dict[str, Any]:
        return self._load_stats()
