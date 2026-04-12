from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

from .audit import AuditTrail
from .config import SecurityConfig
from .detectors import RiskDetector
from .models import RiskFinding, SecurityDecision, ThreatIntelResult
from .threat_intel import ThreatIntelClient

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class OpenClawSecuritySkill:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir or Path(__file__).resolve().parents[1])
        self.config = SecurityConfig.load(self.base_dir)
        self.audit = AuditTrail(self.base_dir)
        self.detector = RiskDetector(self.config)
        self.threat_intel = ThreatIntelClient(self.config, self.audit)

    def before_action(self, event: dict[str, Any]) -> SecurityDecision:
        findings = self.detector.monitor_event(event)
        ti_results: list[ThreatIntelResult] = []

        event_type = str(event.get("event_type", "")).lower()
        url = str(event.get("url", "")).strip()
        target = str(event.get("target", "")).strip()
        path = str(event.get("path", "")).strip()

        if url:
            ti_results.append(self.threat_intel.check_observable(url, "url"))
        elif event_type in {"web_fetch", "browser_open", "file_download", "web_search"} and target:
            if target.startswith(("http://", "https://")) or "." in target:
                ti_results.append(self.threat_intel.check_observable(target))

        if path and event_type in {"open_file", "run_file", "file_download"}:
            ti_results.append(self.threat_intel.check_file(path))

        decision = self._build_decision(findings, ti_results)
        self.audit.log_event(event, decision)
        return decision

    def before_skill_install(self, target: str, **context: Any) -> SecurityDecision:
        if not self.config.preinstall_scan_enabled:
            decision = SecurityDecision(
                status="allowed",
                action="log",
                summary="Pre-installation scan is disabled. Skill installation allowed.",
            )
            event = {
                "event_type": "skill_install",
                "target": target,
                "phase": "pre_install",
                "preinstall_scan_enabled": False,
                **context,
            }
            self.audit.log_event(event, decision)
            return decision

        event = {
            "event_type": "skill_install",
            "target": target,
            "phase": "pre_install",
            **context,
        }
        if target.startswith(("http://", "https://")):
            event["url"] = target
        else:
            event["path"] = target

        decision = self.before_action(event)
        if self._is_preinstall_risky(decision):
            decision.status = "blocked"
            decision.action = "block"
            decision.summary = f"Pre-installation scan blocked skill installation: {decision.summary}"
        return decision

    def handle_command(self, command: str) -> str:
        tokens = shlex.split(self._translate_command_alias(command))
        if not tokens:
            return self.help_text()

        if tokens[0].startswith("/"):
            root = tokens.pop(0).lower()
            if root not in {"/sec", "/security", "/vt", "/threat"}:
                return "Unknown command. Use `/sec help`."

        action = tokens[0].lower() if tokens else "help"
        args = tokens[1:]

        if action in {"help", "-h", "--help"}:
            return self.help_text()

        if action == "status":
            return self._status_text()

        if action == "set-vt-key":
            if not args:
                return "Usage: /sec set-vt-key <API_KEY>"
            self.config.set_vt_api_key(args[0])
            return "VirusTotal API key saved to `.env`."

        if action == "preinstall":
            subaction = args[0].lower() if args else "status"
            if subaction in {"status", "show"}:
                state = "on" if self.config.preinstall_scan_enabled else "off"
                return f"Pre-installation skill scan is {state}."
            if subaction in {"on", "enable", "enabled", "true"}:
                self.config.set_preinstall_scan(True)
                return "Pre-installation skill scan enabled."
            if subaction in {"off", "disable", "disabled", "false"}:
                self.config.set_preinstall_scan(False)
                return "Pre-installation skill scan disabled."
            return "Usage: /sec preinstall <status|on|off>"

        if action == "check":
            if not args:
                return "Usage: /sec check <ip|domain|url|hash>"
            result = self.threat_intel.check_observable(args[0])
            return self._format_ti_result(result)

        if action == "scan":
            if not args:
                return "Usage: /sec scan <file-or-url>"
            target = args[0]
            if target.startswith(("http://", "https://")):
                result = self.threat_intel.check_observable(target, "url")
            else:
                result = self.threat_intel.check_file(target)
            return self._format_ti_result(result)

        if action == "audit":
            subaction = args[0].lower() if args else "show"
            if subaction == "show":
                limit = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
                return self._format_audit_entries(self.audit.read_logs(limit))
            if subaction == "clear":
                cleared = self.audit.clear_logs()
                return f"Cleared {cleared} audit entries."
            return "Usage: /sec audit show [count] | /sec audit clear"

        if action == "stats":
            return json.dumps(self.audit.get_stats(), indent=2)

        if action in {"whitelist", "allowlist", "blacklist", "denylist"}:
            list_name = "whitelist" if action in {"whitelist", "allowlist"} else "blacklist"
            subaction = args[0].lower() if args else "list"

            if subaction == "list":
                entries = getattr(self.config, list_name)
                if not entries:
                    return f"{list_name} is empty."
                return f"{list_name}:\n" + "\n".join(f"- {entry}" for entry in entries)

            if len(args) < 2:
                return f"Usage: /sec {action} add|remove <value>"

            value = args[1]
            if subaction == "add":
                updated = self.config.update_list(list_name, value, add=True)
                return f"Added `{value}` to {list_name}. Total entries: {len(updated)}."
            if subaction in {"remove", "rm", "delete"}:
                updated = self.config.update_list(list_name, value, add=False)
                return f"Removed `{value}` from {list_name}. Total entries: {len(updated)}."
            return f"Usage: /sec {action} add|remove|list <value>"

        if action == "config":
            if len(args) == 3 and args[0].lower() == "action":
                severity = args[1].lower()
                mapping = args[2].lower()
                if severity not in {"low", "medium", "high", "critical"} or mapping not in {"log", "warn", "block"}:
                    return "Usage: /sec config action <low|medium|high|critical> <log|warn|block>"
                self.config.set_action(severity, mapping)
                return f"Severity `{severity}` now maps to `{mapping}`."
            return "Usage: /sec config action <low|medium|high|critical> <log|warn|block>"

        if action == "preflight":
            return self._handle_preflight(args)

        return "Unknown command. Use `/sec help`."

    @staticmethod
    def _translate_command_alias(command: str) -> str:
        stripped = command.strip()
        if not stripped:
            return stripped

        if stripped == "security.audit.show":
            return "/sec audit show 20"
        if stripped.startswith("security.audit.show "):
            count = stripped.split(" ", 1)[1]
            return f"/sec audit show {count}"
        if stripped == "security.audit.clear":
            return "/sec audit clear"
        if stripped == "security.status.show":
            return "/sec status"
        if stripped.startswith("security.vt.setApiKey "):
            api_key = stripped.split(" ", 1)[1]
            return f"/sec set-vt-key {api_key}"

        return stripped

    def help_text(self) -> str:
        return (
            "All-in-One Security commands:\n"
            "- /sec help\n"
            "- /sec status\n"
            "- /sec set-vt-key <API_KEY>\n"
            "- /sec check <ip|domain|url|hash>\n"
            "- /sec scan <file-or-url>\n"
            "- /sec preinstall <status|on|off>\n"
            "- /sec preflight <event_type> <target> [--intent \"...\"] [--command \"...\"] [--payload \"...\"]\n"
            "- /sec audit show [count]\n"
            "- /sec audit clear\n"
            "- /sec whitelist add|remove|list <value>\n"
            "- /sec blacklist add|remove|list <value>\n"
            "- /sec stats"
        )

    def _status_text(self) -> str:
        stats = self.audit.get_stats()
        return (
            f"VirusTotal configured: {'yes' if self.config.vt_api_key else 'no'}\n"
            f"hs-ti enabled: {'yes' if self.config.hs_ti.get('enabled') else 'no'}\n"
            f"Pre-install scan enabled: {'yes' if self.config.preinstall_scan_enabled else 'no'}\n"
            f"Custom TI endpoints: {len(self.config.custom_ti_endpoints)}\n"
            f"Events logged: {stats.get('events', 0)}\n"
            f"Avg TI latency: {stats.get('avg_ti_latency_ms', 0.0)} ms"
        )

    @staticmethod
    def _is_preinstall_risky(decision: SecurityDecision) -> bool:
        if decision.status == "blocked":
            return True

        risky_findings = any(finding.severity in {"high", "critical"} for finding in decision.findings)
        risky_ti = any(
            result.malicious
            or result.score >= 70
            or result.verdict.lower() in {"malicious", "suspicious"}
            for result in decision.ti_results
        )
        return risky_findings or risky_ti

    def _handle_preflight(self, args: list[str]) -> str:
        if len(args) < 2:
            return "Usage: /sec preflight <event_type> <target> [--intent \"...\"] [--command \"...\"] [--payload \"...\"]"

        event_type = args[0]
        target = args[1]
        event: dict[str, Any] = {
            "event_type": event_type,
            "target": target,
        }

        if target.startswith(("http://", "https://")):
            event["url"] = target
        elif Path(target).exists():
            event["path"] = target

        index = 2
        while index < len(args):
            flag = args[index]
            value = args[index + 1] if index + 1 < len(args) else ""
            if flag == "--intent":
                event["intent"] = value
            elif flag == "--command":
                event["command"] = value
            elif flag == "--payload":
                event["payload"] = value
            index += 2

        decision = self.before_action(event)
        return json.dumps(decision.to_dict(), indent=2)

    def _build_decision(
        self,
        findings: list[RiskFinding],
        ti_results: list[ThreatIntelResult],
    ) -> SecurityDecision:
        top_finding = max(
            findings,
            key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0),
            default=None,
        )

        malicious_hit = any(result.malicious or result.score >= 70 for result in ti_results)
        unknown_first_seen = any(result.verdict == "unknown" for result in ti_results)

        if malicious_hit:
            return SecurityDecision(
                status="blocked",
                action="block",
                summary="Threat intelligence flagged the target as malicious or high risk.",
                findings=findings,
                ti_results=ti_results,
            )

        if top_finding:
            action = top_finding.action or self.config.actions.get(top_finding.severity, "warn")
            status = {
                "block": "blocked",
                "warn": "warned",
                "log": "allowed",
            }.get(action, "allowed")
            return SecurityDecision(
                status=status,
                action=action,
                summary=top_finding.title,
                findings=findings,
                ti_results=ti_results,
            )

        if unknown_first_seen:
            return SecurityDecision(
                status="warned",
                action="warn",
                summary="Reputation is unknown for this first-time file or site; review before opening or running it.",
                findings=findings,
                ti_results=ti_results,
            )

        return SecurityDecision(
            status="allowed",
            action="log",
            summary="No immediate security risk detected.",
            findings=findings,
            ti_results=ti_results,
        )

    @staticmethod
    def _format_ti_result(result: ThreatIntelResult) -> str:
        return (
            f"Source: {result.source}\n"
            f"Observable: {result.observable} ({result.observable_type})\n"
            f"Verdict: {result.verdict}\n"
            f"Score: {result.score}/100\n"
            f"Confidence: {result.confidence}\n"
            f"Categories: {', '.join(result.categories) if result.categories else 'n/a'}\n"
            f"Latency: {result.latency_ms} ms\n"
            f"Cached: {'yes' if result.cached else 'no'}"
        )

    @staticmethod
    def _format_audit_entries(entries: list[dict[str, Any]]) -> str:
        if not entries:
            return "No audit entries found."

        lines: list[str] = []
        for entry in entries:
            lines.append(
                f"- {entry.get('timestamp')} | {entry.get('status', 'unknown').upper()} | "
                f"{entry.get('event_type', 'unknown')} | {entry.get('summary', '')}"
            )
        return "\n".join(lines)


def main() -> None:
    skill = OpenClawSecuritySkill()
    args = sys.argv[1:]
    if args and args[0] == "event":
        raw = " ".join(args[1:])
        event = json.loads(raw)
        print(json.dumps(skill.before_action(event).to_dict(), indent=2))
        return

    print(skill.handle_command(" ".join(args) if args else "/sec help"))


if __name__ == "__main__":
    main()
