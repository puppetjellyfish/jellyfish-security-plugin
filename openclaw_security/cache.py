from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class TTLCache:
    def __init__(self, file_path: Path, ttl_seconds: int = 3600, max_items: int = 2048) -> None:
        self.file_path = Path(file_path)
        self.ttl_seconds = ttl_seconds
        self.max_items = max_items
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.file_path.exists():
            return {}
        try:
            return json.loads(self.file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save(self) -> None:
        self.file_path.write_text(
            json.dumps(self._data, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def get(self, key: str) -> Any | None:
        record = self._data.get(key)
        if not record:
            return None

        age = time.time() - record.get("timestamp", 0)
        if age > self.ttl_seconds:
            self._data.pop(key, None)
            self._save()
            return None

        return record.get("value")

    def set(self, key: str, value: Any) -> None:
        if len(self._data) >= self.max_items:
            oldest_key = min(
                self._data.items(),
                key=lambda item: item[1].get("timestamp", 0),
            )[0]
            self._data.pop(oldest_key, None)

        self._data[key] = {
            "timestamp": time.time(),
            "value": value,
        }
        self._save()

    def clear(self) -> None:
        self._data = {}
        self._save()
