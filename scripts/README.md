# Scripts

Automation scripts grouped by **language** first, then by **purpose**.

| Language | Status | Folder |
|----------|--------|--------|
| Bash | Active | [`bash/`](bash/) |
| PowerShell | Planned | [`powershell/`](powershell/) |
| Python | Planned | [`python/`](python/) |

## Suggested Categories

Use the same category names under each language so that equivalent tools are easy to find.

| Category | What goes here |
|----------|----------------|
| `backup/` | Backup creation, verification, restore tests |
| `system/` | OS maintenance: kernel, packages, services, users |
| `monitoring/` | Health checks, alerts, metrics exporters |
| `network/` | DNS, firewall, connectivity, GeoIP |
| `security/` | Auditing, hardening, certificate checks |
| `database/` | DB maintenance, dumps, tuning helpers |
| `cloud/` | Cloud / virtualization APIs |
| `tools/` | Productivity helpers and generators |

## Script Header Template

```bash
#!/usr/bin/env bash
# Name:        script-name.sh
# Purpose:     One-line description
# Requires:    tools / packages / privileges
# Usage:       ./script-name.sh [args]
set -euo pipefail
```
