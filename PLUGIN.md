# Jellyfish Security Plugin

This package is a **native OpenClaw code plugin**.

## Package markers

- `package.json`
- `openclaw.plugin.json`
- `dist/index.js`

## Purpose

The plugin automatically checks:

- prompt / instruction risk
- dangerous commands and behavioral risk
- risky file and browser activity
- VirusTotal reputation for URLs and local files
- skill packages before installation (enabled by default)

Manual admin commands remain available for audit logs, VirusTotal API key management, and pre-install scan control (`/sec preinstall <status|on|off>`).
