from __future__ import annotations

from typing import Any

from .skill import OpenClawSecuritySkill


class OpenClawSecurityPlugin(OpenClawSecuritySkill):
    """Always-on gateway plugin wrapper for the security engine."""

    plugin_id = "jellyfish-security-plugin"
    display_name = "Jellyfish Security Plugin"
    auto_start = True
    monitored_events = (
        "chat",
        "web_fetch",
        "web_search",
        "browser_open",
        "file_download",
        "open_file",
        "run_file",
        "run_command",
    )

    def on_load(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "display_name": self.display_name,
            "auto_start": self.auto_start,
            "monitored_events": list(self.monitored_events),
            "commands": self.get_commands(),
        }

    def on_event(self, event: dict[str, Any]) -> Any:
        return self.before_action(self._normalize_event(event))

    def before_web_fetch(self, url: str, **context: Any) -> Any:
        return self.on_event({"event_type": "web_fetch", "url": url, **context})

    def before_web_search(self, query: str, **context: Any) -> Any:
        return self.on_event({"event_type": "web_search", "target": query, **context})

    def before_browser_open(self, url: str, **context: Any) -> Any:
        return self.on_event({"event_type": "browser_open", "url": url, **context})

    def before_file_download(self, url: str, path: str | None = None, **context: Any) -> Any:
        event = {"event_type": "file_download", "url": url, **context}
        if path:
            event["path"] = path
        return self.on_event(event)

    def before_file_open(self, path: str, **context: Any) -> Any:
        return self.on_event({"event_type": "open_file", "path": path, **context})

    def before_file_run(self, path: str, **context: Any) -> Any:
        return self.on_event({"event_type": "run_file", "path": path, **context})

    def before_command(self, command: str, **context: Any) -> Any:
        return self.on_event({"event_type": "run_command", "command": command, **context})

    def get_commands(self) -> list[dict[str, str]]:
        return [
            {
                "id": "security.audit.show",
                "title": "Security: Show Audit Log",
                "description": "Show recent entries from the automatic security audit trail.",
                "command": "/sec audit show 20",
            },
            {
                "id": "security.audit.clear",
                "title": "Security: Clear Audit Log",
                "description": "Clear saved audit history from the plugin state directory.",
                "command": "/sec audit clear",
            },
            {
                "id": "security.vt.setApiKey",
                "title": "Security: Set VirusTotal API Key",
                "description": "Store or update the VirusTotal key used for automatic reputation checks.",
                "command": "/sec set-vt-key <API_KEY>",
            },
            {
                "id": "security.status.show",
                "title": "Security: Show Status",
                "description": "Display plugin status, provider configuration, and current metrics.",
                "command": "/sec status",
            },
        ]

    def execute_command(self, command_id: str, *args: str) -> str:
        if command_id == "security.audit.show":
            limit = args[0] if args else "20"
            return self.handle_command(f"/sec audit show {limit}")

        if command_id == "security.audit.clear":
            return self.handle_command("/sec audit clear")

        if command_id == "security.vt.setApiKey":
            if not args:
                return "Usage: security.vt.setApiKey <API_KEY>"
            return self.handle_command(f"/sec set-vt-key {args[0]}")

        if command_id == "security.status.show":
            return self.handle_command("/sec status")

        return "Unknown security command ID."

    @staticmethod
    def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(event)

        if "url" not in normalized:
            for key in ("href", "uri", "link", "site"):
                if normalized.get(key):
                    normalized["url"] = normalized[key]
                    break

        if "path" not in normalized:
            for key in ("file", "file_path", "local_path"):
                if normalized.get(key):
                    normalized["path"] = normalized[key]
                    break

        if "command" not in normalized:
            for key in ("cmd", "shell", "script"):
                if normalized.get(key):
                    normalized["command"] = normalized[key]
                    break

        if "payload" not in normalized:
            for key in ("body", "request_body", "content", "text"):
                if normalized.get(key):
                    normalized["payload"] = normalized[key]
                    break

        if "prompt" not in normalized:
            for key in ("message", "query"):
                if normalized.get(key):
                    normalized["prompt"] = normalized[key]
                    break

        if "instructions" not in normalized and normalized.get("system_prompt"):
            normalized["instructions"] = normalized["system_prompt"]

        if "target" not in normalized:
            normalized["target"] = (
                normalized.get("url")
                or normalized.get("path")
                or normalized.get("command")
                or normalized.get("payload")
                or ""
            )

        if "event_type" not in normalized:
            normalized["event_type"] = "chat"

        return normalized
