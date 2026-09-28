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

## RFC edge cases

`test_rfc_edge_cases.py` covers the corners Wireshark cannot vouch for:
template withdrawals, reduced-size encodings, variable-length fields,
padding, structured data lists, and malformed input (set lengths shorter
than their header, truncated templates, ill-formed UTF-8, reserved ids).
Each test builds its datagrams with the helpers in `build.py`, which follow
the RFC wire diagrams, replays them through `--format raw` and asserts on
the output. The behaviour on malformed input is pinned on purpose: a change
there should be a decision, not an accident. `test_sflow_edge_cases.py` does
the same for sFlow v5: expanded samples, the sampled IPv4/IPv6/Ethernet
records, extended gateway, drop samples, unknown formats and bad lengths.

## Wireshark as an oracle

`test_wireshark.py` replays every capture through both `tshark -T json`
and `rustflow collect --format raw`, and checks that the two decodes
agree: first on message headers, sets, templates and record counts, then
on every value of every NetFlow v9/IPFIX data record, and for sFlow on
the common flow each sampled header implies (tshark's dissection of the
frame inside the sample against `--format common`). The comparison
rules live in `oracle.py`; they translate tshark's rendering (absolute
times, split ICMP and applicationId leaves, vendor-decoded private
elements) rather than the other way round, so a mismatch points at the
parser, not the harness.

The tests are skipped when tshark is not installed. It is found on
`PATH`, in the macOS Wireshark bundle, or through `TSHARK`. `editcap`,
which ships with it, trims large captures before replay.

To run the oracle over your own captures, point it at a directory of
pcap files. A file name containing `sflow` is replayed as sFlow, any
other as NetFlow/IPFIX, and only the first `ORACLE_LIMIT` packets are
compared:

```sh
RUSTFLOW_ORACLE_PCAPS=~/pcap uv run pytest test_wireshark.py
```

A `captures.json` in that directory overrides those defaults per file.
`port` is for exporters on a non-standard UDP port: tshark needs to be
told to decode it, while rustflow decodes every UDP payload of a
capture whatever its port.

```json
{
  "meir.pcap": {"port": 8008},
  "big-sflow.pcap": {"limit": 500},
  "odd-name.pcap": {"flow_type": "sflow"}
}
```
