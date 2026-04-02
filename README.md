# jellyfish-security-plugin

Puppetjellyfish's always-on **native OpenClaw code plugin** for automatic prompt-risk, behavioral-risk, and reputation-based threat checks before risky actions run.

## Features

- Auto-start plugin behavior: checks run **without user input** whenever monitored events occur
- Detects prompt injection / instruction override attempts
- Flags dangerous commands, risky file writes, and suspicious API usage
- Detects secret leakage and PII exposure
- Warns when sensitive data is about to be sent to LLM providers
- Detects intent–action mismatch
- Monitors browser, web fetch, search, file download, file open, and file run events
- Checks IPs, domains, URLs, and file hashes
- Integrates with VirusTotal, Hillstone Threat Intelligence (`hs-ti`), and custom TI APIs
- Supports block / warn / log policies, allowlists, blocklists, audit logs, metrics, and caching

## Native Plugin Package Markers

This repo now includes the native package files OpenClaw and ClawHub expect for a real plugin install:

- `package.json`
- `openclaw.plugin.json`
- `dist/index.js`

## Quick Start

```powershell
cd c:\ALLY\diyskills\all-in-one-security
pip install -r requirements.txt
copy .env.example .env
```

Set your VirusTotal API key:

```text
/sec set-vt-key <YOUR_API_KEY>
```

Run a manual IOC check:

```powershell
python -m openclaw_security /sec check https://example.org/payload.exe
```

Show audit history:

```powershell
python -m openclaw_security /sec audit show 20
```

## Gateway Integration Example

```python
from openclaw_security import OpenClawSecurityPlugin

plugin = OpenClawSecurityPlugin()

event = {
    "event_type": "file_download",
    "url": "https://downloads.example.org/tool.exe",
    "intent": "download a driver update",
}

decision = plugin.on_event(event)

if decision.status == "blocked":
    raise RuntimeError(decision.summary)
elif decision.status == "warned":
    print(decision.summary)
```

## Gateway Chat Commands

- `/sec help`
- `/sec status`
- `/sec set-vt-key <API_KEY>`
- `/sec check <ip|domain|url|hash>`
- `/sec scan <file-or-url>`
- `/sec preflight <event_type> <target> [--intent "..."]`
- `/sec audit show [count]`
- `/sec audit clear`
- `/sec whitelist add|remove|list <value>`
- `/sec blacklist add|remove|list <value>`
- `/sec stats`

## Why this now shows as a plugin

The repo now ships with the standard native plugin manifests, so it should be detected under the **Plugins** family instead of only as a skill-style package.

## Manual Admin Commands

These remain available even though the plugin runs automatically:

- `security.audit.show`
- `security.audit.clear`
- `security.vt.setApiKey`
- `security.status.show`
- Slash-command equivalents under `/sec ...`

## Caveats

- VirusTotal free-tier rate limits still apply.
- Uploading unknown files to VirusTotal is **disabled by default** to avoid privacy leakage; enable it in `config/security_config.json` if desired.
- This project ships as a **drop-in plugin scaffold** and may need minor adapter changes depending on your exact OpenClaw gateway runtime.

