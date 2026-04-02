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

Manual admin commands remain available for audit logs and VirusTotal API key management.
