# Bash Scripts

| Category | Script | Description |
|----------|--------|-------------|
| [`backup/`](backup/) | `backup-check.sh` | Weekly backup inventory per server with GeoIP classification |
| [`system/`](system/) | `keep_newkernel.sh` | Switch to a target kernel and remove the old one (EL9) |
| [`tools/`](tools/) | `mobaxterm_sessions_gen.sh` | Generate MobaXterm sessions from a server list |

## Conventions

- Shebang `#!/bin/bash`, LF line endings (enforced by `.gitattributes`).
- Prefer `set -euo pipefail` for scripts that change the system.
- Clean up temporary files with `trap ... EXIT`.
- Make scripts executable: `chmod +x script.sh`.
