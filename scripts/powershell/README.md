# PowerShell Scripts

Planned home for Windows-side automation.

Suggested categories (create the folder when the first script is added):

- `system/` — Windows maintenance and inventory
- `ad/` — Active Directory / users / groups
- `network/` — connectivity, DNS, firewall checks
- `cloud/` — Azure / Microsoft 365 automation
- `tools/` — local helpers

Conventions:

- Files `verb-noun.ps1` (e.g. `get-diskreport.ps1`).
- Use `[CmdletBinding()]`, a `param()` block and comment-based help (`.SYNOPSIS`, `.EXAMPLE`).
- `.gitattributes` keeps `.ps1` files in CRLF.
