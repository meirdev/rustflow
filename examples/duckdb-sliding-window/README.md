# rustflow → Parquet → DuckDB sliding-window rates

rustflow writes normalised flows to Parquet files rotated every 10 seconds. A
small Python watcher picks each finished file up the moment it appears, loads
it into DuckDB, and every reporting interval prints the bit and packet rate of
each destination prefix over a sliding window.

```text
NetFlow / IPFIX / sFlow (UDP 9995)
        │
        ▼
  rustflow collect -s parquet -i 10s -o flows/
        │   flows/flows-20260906T194040Z.parquet, one file per 10 s
        ▼
  watch.py  (watchfiles ── new file ──► DuckDB `flows` table)
        │   every 10 s: 60-second window ──► MERGE INTO `dst_rates`
        ▼
  terminal: top destination /24 (IPv4) and /48 (IPv6) prefixes by bps
```

The watcher follows the *materialised view* pattern from DuckDB's
[streaming patterns](https://duckdb.org/2025/10/13/duckdb-streaming-patterns)
post: raw events are appended incrementally, an aggregate is `MERGE`d into a
materialised table on a schedule, and rows that can no longer affect any
result are deleted.

## Run

Three terminals, all from this directory.

Collector, one Parquet file every 10 seconds:

```bash
rustflow collect -t netflow -p 9995 -f common -s parquet -o ./flows -i 10s
```

Watcher:

```bash
uv run watch.py ./flows
```

Traffic, either real exporters pointed at UDP 9995 or the built-in generator:

```bash
rustflow generate -p 9995 -r 20 --dst-cidr 192.168.0.0/22
```

After the first rotation the watcher prints something like:

```text
[22:41:15] window 19:40:08..19:41:08 UTC | 1 new files | 4 prefixes | 22.7 Mbps | 4.3 Kpps
  dst_prefix                 flows          bps          pps
  192.168.3.0/24              1317     5.9 Mbps     1.1 Kpps
  192.168.1.0/24              1318     5.7 Mbps     1.1 Kpps
  192.168.2.0/24              1275     5.6 Mbps     1.1 Kpps
  192.168.0.0/24              1290     5.6 Mbps     1.1 Kpps
```

## Options

| flag | default | meaning |
|---|---|---|
| `--every SECONDS` | 10 | how often a report is printed |
| `--window SECONDS` | 60 | sliding window length the rates are averaged over |
| `--top N` | 20 | prefixes to print, highest bps first |
| `--db FILE` | `flows.duckdb` | DuckDB database; `:memory:` keeps nothing between runs |
| `--once` | | load whatever is on disk, print one report, exit |

## How it works

**Complete files only.** rustflow writes each rotating file under a hidden
`.flows-….parquet.tmp` name and renames it once the Parquet footer is on disk.
`watchfiles` reports that rename as a new `*.parquet` file, so the watcher
never reads a half-written file. Files already present at startup are loaded
first, and a `loaded_files` table makes every load idempotent, so restarting
the watcher with the same `--db` continues where it left off.

**Load.** Each new file is read with `read_parquet` and appended to a narrow
`flows` table holding only what the aggregate needs. The destination prefix is
computed at load time with the `inet` extension: `network((dst_addr || '/24')::INET)`
for IPv4 and `/48` for IPv6. Bytes and packets are multiplied by the flow's
`sampling_rate` so sampled exporters report the traffic they represent.

**Aggregate.** Every `--every` seconds the window `(latest time_received - window,
latest time_received]` is aggregated per prefix, and the result is `MERGE`d into
`dst_rates`. `bps` is `sum(bytes) * 8 / window` and `pps` is
`sum(packets) / window`. Prefixes with no traffic in the current window are
removed, and raw rows older than two windows are deleted.

The window is anchored to the newest `time_received` in the data rather than
the wall clock, so it also works when replaying a pcap, and it is not skewed by
the 10-second rotation delay of the newest file.

**Persistence.** With the default `--db flows.duckdb`, `dst_rates` is an
ordinary table that any other DuckDB client can query while the watcher runs.

## Notes

- Only the destination prefix is keyed. Add `sampler_address` or the source
  prefix to the `GROUP BY` and the `MERGE` key if you need them.
- The window length should be at least the exporters' active timeout, since a
  flow record reports the traffic accumulated since the previous report.
