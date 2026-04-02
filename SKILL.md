---
name: all-in-one-security
displayName: All-in-One Security Guard
version: 1.0.0
description: OpenClaw security plugin for always-on prompt-risk, behavior-risk, data-risk, intent mismatch, and threat-intel preflight checks.
entrypoint: openclaw_security.plugin:OpenClawSecurityPlugin
kind: plugin
autoStart: true
monitors:
  - web_fetch
  - web_search
  - browser_open
  - file_download
  - open_file
  - run_file
commands:
  - /sec help
  - /sec status
  - /sec check <ioc>
  - /sec scan <path-or-url>
  - /sec preflight <event_type> <target> [--intent "..."]
  - /sec audit show [count]
  - /sec audit clear
  - /sec set-vt-key <api_key>
  - /sec whitelist add|remove|list <value>
  - /sec blacklist add|remove|list <value>
  - /sec stats
---

# All-in-One Security Guard Plugin

This OpenClaw plugin runs as an **always-on security gate** before risky agent actions. It is designed for gateway-level enforcement and supports:

- **Prompt / instruction risk** detection
- **Behavioral risk** detection
  - dangerous commands
  - risky file actions
  - suspicious API calls
- **Data risk** detection
  - secret leakage
  - PII exposure
  - sending sensitive data to LLMs
- **Intent–action mismatch** detection
- Automatic monitoring for:
  - `web_fetch`
  - `web_search`
  - `browser_open`
  - `file_download`
  - `open_file`
  - `run_file`
- Threat intelligence checks for:
  - IPs
  - domains
  - URLs
  - file hashes (`MD5`, `SHA1`, `SHA256`)
- Threat intel providers:
  - **VirusTotal**
  - **hs-ti / Hillstone Threat Intelligence**
  - **custom TI APIs**
- Configurable actions:
  - `block`
  - `warn`
  - `log`
- Policy and observability:
  - whitelist / blacklist
  - audit logs
  - stats
  - cache and latency metrics

## Gateway Commands

```text
/sec help
/sec status
/sec set-vt-key <API_KEY>
/sec check <ip|domain|url|hash>
/sec scan <local-file-or-url>
/sec preflight <event_type> <target> [--intent "..."] [--command "..."] [--payload "..."]
/sec audit show [count]
/sec audit clear
/sec whitelist add <value>
/sec whitelist remove <value>
/sec whitelist list
/sec blacklist add <value>
/sec blacklist remove <value>
/sec blacklist list
/sec stats
```

## Automatic Plugin Hook

Register `OpenClawSecurityPlugin` as an auto-start plugin and let the gateway call `OpenClawSecurityPlugin.on_event(event)` or `before_action(event)` before executing an action. Example event payload:

```json
{
  "event_type": "browser_open",
  "url": "https://example.org/file.exe",
  "intent": "check if the site is safe",
  "payload": "optional request body or prompt",
  "command": "optional shell command",
  "path": "optional local path"
}
```

The method returns a security decision with `allowed`, `warned`, or `blocked` status and records an audit trail entry.

## Notes

- First-time file/site checks will query **VirusTotal** when configured.
- If reputation is **unknown**, the skill can **warn** instead of silently allowing execution.
- `hs-ti` and custom TI providers are configured in `config/security_config.json`.
