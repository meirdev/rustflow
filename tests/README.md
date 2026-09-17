# rustflow tests

End-to-end tests for the `rustflow` binary.

## Running

The tests need a built binary and [uv](https://docs.astral.sh/uv/).

```sh
cargo build --release          # from the repository root
cd tests
uv run pytest
```

The binary is looked up under `target/release/` then `target/debug/`.

Set `RUSTFLOW_BIN` to test another build:

```sh
RUSTFLOW_BIN=/path/to/rustflow uv run pytest
```

## Layout

```
fixtures/
  pcap/             one capture per protocol: netflow_v5, netflow_v9, ipfix, sflow_v5
  snapshots/        expected output, <pcap>.<variant>.<ext>
  csv/              networks.csv (prefix lookup), protocols.csv (exact lookup)
  mmdb/             country.mmdb, asn.mmdb (small hand-built databases)
```

The captures are synthetic. They are shaped like real exporters, including
templates sent ahead of data for v9 and IPFIX, and use only documentation
address ranges.

## Variants

Every pcap is run through nine variants:

| variant  | `--format` | `--serialization`              | snapshot extension |
| -------- | ---------- | ------------------------------ | ------------------ |
| raw      | raw        | ndjson                         | `.raw.ndjson`      |
| common   | common     | ndjson, csv, protobuf, parquet | `.common.<ext>`    |
| enriched | common     | ndjson, csv, protobuf, parquet | `.enriched.<ext>`  |

Protobuf snapshots have the `.pb` extension. Parquet is stored as
`.parquet.txt`: the Arrow schema followed by one JSON row per line, so a
failing diff is readable and the file is stable across Parquet writers.

The enriched variant adds four sources through `--enrich`, defined by the
`enrich_args` fixture in `conftest.py`:

- `mmdb/country.mmdb`: `src_country`, `dst_country`
- `mmdb/asn.mmdb`: `src_asn`, `src_as_org`, `dst_asn`, `dst_as_org`
- `csv/networks.csv` by prefix: `csv_src_asn`, `csv_src_country`, `next_hop_org`
- `csv/protocols.csv` by exact match: `proto_name`

## Updating a snapshot

When an output change is intended, regenerate the affected snapshot with
the same command the test runs and review the diff before committing:

```sh
./target/release/rustflow collect --flow-type netflow \
  --pcap tests/fixtures/pcap/ipfix_sanity.pcap \
  --format common --serialization ndjson \
  > tests/fixtures/snapshots/ipfix.common.ndjson
```

For the enriched variant, pass the `--enrich` arguments from `conftest.py`.
For Parquet, write to a file with `--output` and convert it with the
`parquet_as_text` helper in `test_sanity.py`.
