from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = {
    "actions": {
        "low": "log",
        "medium": "warn",
        "high": "warn",
        "critical": "block",
    },
    "whitelist": ["virustotal.com", "www.virustotal.com"],
    "blacklist": [],
    "trusted_domains": [],
    "upload_unknown_files": False,
    "preinstall_scan_enabled": True,
    "cache_ttl_seconds": 3600,
    "request_timeout_seconds": 8,
    "custom_ti_endpoints": [],
    "hs_ti": {
        "enabled": False,
        "base_url": "",
        "api_key": "",
        "auth_header": "Authorization",
        "observable_path": "/lookup",
        "method": "GET",
        "value_param": "value",
        "type_param": "type",
    },
}


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _write_env_value(path: Path, key: str, value: str) -> None:
    existing = _read_env_file(path)
    existing[key] = value
    lines = [f"{env_key}={env_value}" for env_key, env_value in sorted(existing.items())]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@dataclass
class SecurityConfig:
    base_dir: Path
    actions: dict[str, str] = field(default_factory=lambda: DEFAULT_CONFIG["actions"].copy())
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[str] = field(default_factory=list)
    trusted_domains: list[str] = field(default_factory=list)
    upload_unknown_files: bool = False
    preinstall_scan_enabled: bool = True
    cache_ttl_seconds: int = 3600
    request_timeout_seconds: int = 8
    custom_ti_endpoints: list[dict[str, Any]] = field(default_factory=list)
    hs_ti: dict[str, Any] = field(default_factory=lambda: DEFAULT_CONFIG["hs_ti"].copy())
    vt_api_key: str = ""

    @property
    def config_path(self) -> Path:
        return self.base_dir / "config" / "security_config.json"

    @property
    def env_path(self) -> Path:
        return self.base_dir / ".env"

    @classmethod
    def load(cls, base_dir: str | Path) -> "SecurityConfig":
        base = Path(base_dir)
        config_path = base / "config" / "security_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        if not config_path.exists():
            config_path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")

        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        env_values = {**_read_env_file(base / ".env"), **os.environ}
        hs_ti = {**DEFAULT_CONFIG["hs_ti"], **loaded.get("hs_ti", {})}

        return cls(
            base_dir=base,
            actions={**DEFAULT_CONFIG["actions"], **loaded.get("actions", {})},
            whitelist=loaded.get("whitelist", DEFAULT_CONFIG["whitelist"]),
            blacklist=loaded.get("blacklist", []),
            trusted_domains=loaded.get("trusted_domains", []),
            upload_unknown_files=bool(loaded.get("upload_unknown_files", False)),
            preinstall_scan_enabled=bool(loaded.get("preinstall_scan_enabled", True)),
            cache_ttl_seconds=int(loaded.get("cache_ttl_seconds", 3600)),
            request_timeout_seconds=int(loaded.get("request_timeout_seconds", 8)),
            custom_ti_endpoints=loaded.get("custom_ti_endpoints", []),
            hs_ti=hs_ti,
            vt_api_key=env_values.get("VIRUSTOTAL_API_KEY", ""),
        )

    def save(self) -> None:
        payload = {
            "actions": self.actions,
            "whitelist": self.whitelist,
            "blacklist": self.blacklist,
            "trusted_domains": self.trusted_domains,
            "upload_unknown_files": self.upload_unknown_files,
            "preinstall_scan_enabled": self.preinstall_scan_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
            "custom_ti_endpoints": self.custom_ti_endpoints,
            "hs_ti": {
                **self.hs_ti,
                "api_key": "",
            },
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def set_vt_api_key(self, api_key: str) -> None:
        self.vt_api_key = api_key.strip()
        _write_env_value(self.env_path, "VIRUSTOTAL_API_KEY", self.vt_api_key)

    def set_action(self, severity: str, action: str) -> None:
        self.actions[severity] = action
        self.save()

    def set_preinstall_scan(self, enabled: bool) -> None:
        self.preinstall_scan_enabled = enabled
        self.save()

    def update_list(self, list_name: str, value: str, add: bool = True) -> list[str]:
        current = list(getattr(self, list_name))
        if add:
            if value not in current:
                current.append(value)
        else:
            current = [item for item in current if item != value]
        setattr(self, list_name, current)
        self.save()
        return current

    def is_whitelisted(self, value: str) -> bool:
        lowered = value.lower()
        return any(item.lower() in lowered for item in self.whitelist)

    def is_blacklisted(self, value: str) -> bool:
        lowered = value.lower()
        return any(item.lower() in lowered for item in self.blacklist)
