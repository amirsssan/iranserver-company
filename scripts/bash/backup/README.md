# Backup Scripts

## backup-check.sh

Builds a **backup inventory report** for every hosting server found under `/home`.

### What it does

1. Scans `/home/lh*`, `/home/wh*` and `/home/sonic*`. Only names matching `^(lh|wh|sonic)[0-9]+$` are used.
2. Resolves `<server>.<DOMAIN>` to an IPv4 address with `getent ahostsv4`.
3. Detects the server country by GeoIP, using `mmdblookup` (MaxMind `GeoLite2/GeoIP2-Country.mmdb`) and falling back to `geoiplookup`.
4. Recursively counts files and total size in `weekly1/` and `weekly2/`.
   - `lh` and `wh` servers keep files directly in these directories.
   - `sonic` servers keep date-named subdirectories.
5. Assigns a status per server and prints three tables: **IRAN**, **FOREIGN**, **UNKNOWN**.
6. Prints a final task summary with counts per location, server type and status.

### Status values

| Status | Meaning |
|--------|---------|
| `BOTH` | Files exist in both `weekly1` and `weekly2` |
| `ONLY-WEEKLY1` | Files exist only in `weekly1` |
| `ONLY-WEEKLY2` | Files exist only in `weekly2` |
| `NO-BACKUP` | No backup files found |
| `NO-IP` | The hostname does not resolve (reported under UNKNOWN) |

### Configuration

Variables at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE` | `/home` | Directory containing the server folders |
| `DOMAIN` | `irandns.com` | Domain appended to the server name for DNS lookup |

### Requirements

- `bash`, `find` (GNU, for `-printf`), `awk`, `getent`, `numfmt` (coreutils)
- Optional but recommended: `mmdblookup` + a MaxMind country DB, or `geoiplookup`. Without them, servers are reported as `UNKNOWN`.

### Usage

```bash
chmod +x backup-check.sh
./backup-check.sh | tee backup-report-$(date +%F).txt
```

### Sample output layout

```text
SERVER     IP               LOCATION        WEEKLY1 (files / size)  WEEKLY2 (files / size)  STATUS
---------- ---------------- ------------ --------------------- --------------------- ----------------
lh123      203.0.113.10     IRAN                  42 / 12GiB            40 / 11GiB     BOTH
```

### Design notes

- Temporary files are created with `mktemp` and removed by `trap ... EXIT`.
- The script is read-only: it never modifies or deletes backups.
- The recursive scan is intentional so that all three server layouts are handled by one code path.
