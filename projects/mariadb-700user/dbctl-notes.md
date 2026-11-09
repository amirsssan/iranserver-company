# Notes: `dbctl` Limits and File Descriptors

## systemd file-descriptor limit

```bash
systemctl show mariadb -p LimitNOFILE
# LimitNOFILE=1048576
```

This is higher than `open_files_limit = 200000` in [`my.cnf`](my.cnf), so MariaDB can use the full value.

## Per-user limits with `dbctl` (DB Governor)

Show the current limits:

```text
# dbctl list
 user             cpu(%)                     read(MB/s)                        write(MB/s)
default           400/380/350/300            953/791/724/562                   953/791/724/562
```

The four numbers in each column are the limits for four time windows (current / short / mid / long).

Raise the `default` limits:

```bash
dbctl set default \
  --cpu=500,475,435,375 \
  --read=8388608,6962545,6375342,4949197 \
  --write=8388608,6962545,6375342,4949197
```

Result:

```text
# dbctl list
 user             cpu(%)                     read(MB/s)                        write(MB/s)
default           500/475/435/375            8388608/6962545/6375342/494       8388608/6962545/6375342/494
```

> The last value in the `read` and `write` columns shows as `494` because the `dbctl list` output is truncated. The value that was set is `4949197`.
