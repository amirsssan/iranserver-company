# MariaDB Tuning for a 700-Account Shared-Hosting Server

## Problem

A single MariaDB server serves about **700 shared-hosting accounts** on hardware with **245 GB RAM and 53 CPU cores** (NVMe storage). The goals were to:

- Handle many concurrent connections without exhausting RAM (OOM).
- Reduce idle / hanging connections.
- Keep a large number of tables open (many small databases).
- Limit the impact of any single account on the others.

## Files

| File | Purpose |
|------|---------|
| [`my.cnf`](my.cnf) | Tuned MariaDB configuration |
| [`health-check.sql`](health-check.sql) | Status / variable queries to measure the effect of the tuning |
| [`dbctl-notes.md`](dbctl-notes.md) | Per-user CPU and IO limits with `dbctl` (DB Governor) and systemd file-descriptor limit |

## Key Decisions in `my.cnf`

| Area | Setting | Reason |
|------|---------|--------|
| InnoDB memory | `innodb_buffer_pool_size = 148G`, `innodb_buffer_pool_instances = 32` | About 60% of RAM, leaving headroom for the OS and other processes |
| Durability vs. speed | `innodb_flush_log_at_trx_commit = 2`, `sync_binlog = 0` | Large write-speed gain on shared hosting, with a small risk (up to ~1 s of transactions on OS crash) |
| Disk I/O | `innodb_flush_method = O_DIRECT`, `innodb_io_capacity = 10000` / `20000`, `innodb_flush_neighbors = 0` | Suited for NVMe |
| Connections | `max_connections = 800`, `max_user_connections = 30`, `wait_timeout = 30` | Cap per-account usage and drop idle connections quickly |
| Per-connection buffers | `read/sort/join_buffer_size` 256K–512K | Buffers multiplied by `max_connections` must not cause OOM |
| Table cache | `table_open_cache = 80000`, `table_definition_cache = 50000`, `open_files_limit = 200000` | Many small databases from many accounts |
| Temp tables | `tmp_table_size = max_heap_table_size = 64M` | Limits memory use per temporary table |
| Query cache | Disabled | Avoids global mutex contention |
| Slow log | `long_query_time = 2` | Find problematic queries |

## How to Verify

1. Apply the settings and restart MariaDB.
2. Confirm the file-descriptor limit:
   ```bash
   systemctl show mariadb -p LimitNOFILE
   ```
3. Run the queries in [`health-check.sql`](health-check.sql) and watch:
   - `Max_used_connections` / `Threads_connected` against `max_connections`
   - `Opened_tables` growth against `table_open_cache`
   - `Created_tmp_disk_tables` against `Created_tmp_tables`
   - `Innodb_buffer_pool_*` hit ratio

## Notes

- Adjust the values to the actual RAM, CPU and disk before reusing them.
- Do not copy `innodb_flush_log_at_trx_commit = 2` to systems that cannot lose any committed transaction.
