# Output

RustFlow supports two flow representations:

- **Raw** - preserves the original protocol-specific flow structure.
- **Common** - normalizes NetFlow, IPFIX, and sFlow into a common schema.

The common format can be serialized as **NDJSON, CSV, Protobuf, Parquet, or Arrow IPC**, or discarded entirely for load testing.

## Common Flow

The common flow format provides a consistent schema across the supported flow protocols.

| Field                   | Type      | Optional | Description                                                                                                                                            |
| ----------------------- | --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `flow_type`             | string    | No       | Source flow protocol/type                                                                                                                              |
| `time_received_ns`      | timestamp | No       | Time the flow was received                                                                                                                             |
| `sampler_address`       | string    | No       | Address of the flow exporter/sampler                                                                                                                   |
| `sequence_num`          | uint32    | No       | Export packet sequence number                                                                                                                          |
| `sampling_rate`         | uint32    | Yes      | Sampling rate reported by the exporter                                                                                                                 |
| `time_flow_start_ns`    | timestamp | Yes      | Flow start time                                                                                                                                        |
| `time_flow_end_ns`      | timestamp | Yes      | Flow end time                                                                                                                                          |
| `bytes`                 | uint64    | Yes      | Number of bytes in the flow                                                                                                                            |
| `packets`               | uint64    | Yes      | Number of packets in the flow                                                                                                                          |
| `src_addr`              | string    | Yes      | Source IPv4 or IPv6 address                                                                                                                            |
| `dst_addr`              | string    | Yes      | Destination IPv4 or IPv6 address                                                                                                                       |
| `src_mac`               | string    | Yes      | Source MAC address                                                                                                                                     |
| `dst_mac`               | string    | Yes      | Destination MAC address                                                                                                                                |
| `etype`                 | uint16    | Yes      | Ethernet EtherType                                                                                                                                     |
| `proto`                 | uint8     | Yes      | IP protocol number                                                                                                                                     |
| `src_port`              | uint16    | Yes      | Source transport port                                                                                                                                  |
| `dst_port`              | uint16    | Yes      | Destination transport port                                                                                                                             |
| `in_if`                 | uint32    | Yes      | Input interface index                                                                                                                                  |
| `out_if`                | uint32    | Yes      | Output interface index                                                                                                                                 |
| `ip_tos`                | uint8     | Yes      | IP Type of Service / traffic class                                                                                                                     |
| `ip_ttl`                | uint8     | Yes      | IP TTL / hop limit                                                                                                                                     |
| `tcp_flags`             | uint16    | Yes      | TCP flags bitmask                                                                                                                                      |
| `icmp_type`             | uint8     | Yes      | ICMP type                                                                                                                                              |
| `icmp_code`             | uint8     | Yes      | ICMP code                                                                                                                                              |
| `ipv6_flow_label`       | uint32    | Yes      | IPv6 flow label                                                                                                                                        |
| `fragment_id`           | uint32    | Yes      | IP fragment identifier                                                                                                                                 |
| `fragment_offset`       | uint16    | Yes      | IP fragment offset                                                                                                                                     |
| `src_as`                | uint32    | Yes      | Source autonomous system number                                                                                                                        |
| `dst_as`                | uint32    | Yes      | Destination autonomous system number                                                                                                                   |
| `next_hop`              | string    | Yes      | IP next-hop address                                                                                                                                    |
| `src_net`               | uint8     | Yes      | Source prefix length                                                                                                                                   |
| `dst_net`               | uint8     | Yes      | Destination prefix length                                                                                                                              |
| `bgp_next_hop`          | string    | Yes      | BGP next-hop address                                                                                                                                   |
| `src_vlan`              | uint16    | Yes      | Source VLAN ID                                                                                                                                         |
| `dst_vlan`              | uint16    | Yes      | Destination VLAN ID                                                                                                                                    |
| `observation_domain_id` | uint32    | Yes      | IPFIX observation domain ID                                                                                                                            |
| `forwarding_status`     | uint32    | Yes      | NetFlow v9 / IPFIX forwarding status. In its low byte, the top two bits are forwarded (1), dropped (2) or consumed (3) and the low six bits the reason |

Fields that are unavailable in the original flow record are left unset.

`flow_type` is one of `NETFLOW_V5`, `NETFLOW_V9`, `IPFIX`, or `SFLOW_V5`.

After the flow's fields come the [extra fields](collector.md#extra-fields), then the
[enrichment](enrichment.md) fields, each a column of its own in every serialization.
[`--fields`](collector.md#selecting-fields) writes only the columns it lists.

## NDJSON

Each flow is serialized as a single JSON object per line.

Optional fields that do not have a value are omitted.

```json
{
  "flow_type": "IPFIX",
  "time_received_ns": 1700000003000000000,
  "sampler_address": "192.0.2.1",
  "sequence_num": 1234,
  "bytes": 1500,
  "packets": 10,
  "src_addr": "192.0.2.10",
  "dst_addr": "198.51.100.20",
  "proto": 6,
  "src_port": 54321,
  "dst_port": 443
}
```

## CSV

CSV output has a column for each common flow field, then one for each extra and enrichment field.

```text
flow_type,time_received_ns,sampler_address,sequence_num,sampling_rate,...,forwarding_status
```

Fields without a value are represented as empty CSV values.

## Parquet

Parquet output uses the same common flow schema with native Arrow data types.

String-based fields such as IP and MAC addresses are stored as UTF-8 strings, while numeric fields use their corresponding unsigned integer types.

Timestamp fields are stored using the Parquet/Arrow timestamp representation.

## File Output

By default, RustFlow writes output to stdout.

Use `--output` (`-o`) to write flows to a file:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s ndjson \
  -o flows.ndjson
```

Without `--interval`, `--output` refers to a single file.

> Parquet output requires `--format common`. A Parquet file is only readable once its footer is written, so it cannot stream; with `-s parquet` and no `--output`, RustFlow writes an Arrow IPC stream to stdout instead.

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows.parquet
```

Parquet output is compressed using Snappy.

## Protobuf

`-s protobuf` writes a stream of protobuf messages using the schema in
[`crates/rustflow_collect/proto/rustflow.proto`](../crates/rustflow_collect/proto/rustflow.proto).
It requires `--format common`, and files use the `.pb` extension.

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s protobuf \
  -o flows.pb
```

Protobuf messages are **length-delimited**: each message is prefixed with its size as a varint.

Each extra field and enrichment field is a field of the message, with a number of its own
from 1000 up: the number given with the field, or else the next free one in the order of the
columns. Give the numbers yourself when files must stay readable after the fields change,
since adding or removing a field moves the automatic ones.

To read these fields, add them to the `CommonFlow` message in your copy of the schema. The
collector logs the lines when it starts:

```text
Add to CommonFlow in rustflow.proto: optional uint64 vrf = 1000;
Add to CommonFlow in rustflow.proto: optional string src_country = 1001;
```

A reader without them still reads the flow's own fields. Unsigned values are `uint64`, signed
`sint64`, floats `double`, booleans `bool`, timestamps `int64`, strings `string`, and addresses,
MAC addresses and octet arrays `bytes`.

## Discard

`-s discard` decodes and counts flows without writing them anywhere. Flows are still
parsed and reported through the Prometheus metrics, which makes it useful for measuring
ingest throughput without paying for serialization or disk:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s discard
```

## File Rotation

Use `--interval` (`-i`) to start a new output file at a fixed interval.

When `--interval` is used, `--output` refers to the root directory of the output tree instead of a single file.

For example:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m
```

This creates a new output file every 10 minutes. An interval in which no flows arrive produces no file.

A custom file name prefix can be specified with `--prefix`:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m \
  --prefix netflow
```

Files are named using the prefix and timestamp, for example:

```text
netflow-20260820T120000Z.parquet
```

## Running a command per file

Use `-x` to run a command after each rotated file is complete:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m \
  --level 2 \
  -x "aws s3 cp %f s3://bucket/flows/%p"
```

Placeholders in the command are replaced for each file:

| Placeholder | Value                                                                                                 |
| ----------- | ----------------------------------------------------------------------------------------------------- |
| `%f`        | The file's path                                                                                       |
| `%p`        | The file's path below the output directory, `2026/08/20/12/flows-20260820T120000Z.parquet` at level 2 |
| `%t`        | The window start as in the file name, `20260820T120000Z`                                              |
| `%u`        | The window start as a Unix timestamp                                                                  |
| `%%`        | A percent sign                                                                                        |

`-x` requires `--interval`.

## Expiring old files

Use `--expire` to remove rotated files once they are older than a given age:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m \
  --expire 30d
```

A file's age is taken from the window stamp in its name. The check runs at
startup and then every hour, or more often for a short retention, so a file may
be removed a little after it reaches the age. It only touches files of the
collector's own prefix and serialization, and removes partition directories it
leaves empty.

`--expire` requires `--interval` and must be at least as long.

Use `--expire-exec` to run a command after each removal, with the same
placeholders as `-x`:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m \
  --expire 30d \
  --expire-exec "logger expired %p"
```

The file is already removed when the command runs. A command that fails is
counted in `output_hook_errors`.

## Partitioning

Rotated output can be organized into time-based directory partitions using `--level` (`-l`).

| Level  | Directory layout                                 |
| ------ | ------------------------------------------------ |
| (none) | Flat output directory                            |
| `1`    | `%Y/%m/%d`                                       |
| `2`    | `%Y/%m/%d/%H`                                    |
| `3`    | `%Y/%m/%d/%H` with an additional 5-minute bucket |

`--level` requires `--interval`, and the interval must divide the directory's
period, a day, an hour or 5 minutes, so that every file in a directory holds
flows received in that period. Windows are aligned to the clock, so a 5-minute
interval gives files at 13:55, 14:00, 14:05 and so on.

For example:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 5m \
  --level 2
```

This produces an output tree similar to:

```text
flows/
└── 2026/
    └── 08/
        └── 20/
            └── 12/
                ├── flows-20260820T120000Z.parquet
                ├── flows-20260820T120500Z.parquet
                └── flows-20260820T121000Z.parquet
```

For level `3`, files are additionally grouped into 5-minute buckets below the hour directory.

### Hive partitioning

With `--hive`, the directories are named the way query engines expect, as
`key=value`:

| Level | Directory layout                                     |
| ----- | ---------------------------------------------------- |
| `1`   | `date=%Y-%m-%d`                                      |
| `2`   | `date=%Y-%m-%d/hour=%H`                              |
| `3`   | `date=%Y-%m-%d/hour=%H/minute=%M`, in 5-minute steps |

DuckDB, Spark, DataFusion and the like then read `date`, `hour` and `minute`
as columns and skip the directories a query rules out, without opening a
file. With a 10-second interval and 30 days kept, that is the difference
between reading 360 files and 260,000:

```sql
SELECT hour, sum(bytes * sampling_rate) * 8 / 3600 AS bits_per_second
FROM read_parquet('flows/**/*.parquet', hive_partitioning = true)
WHERE date = '2026-08-27' AND hour BETWEEN 12 AND 13
GROUP BY hour ORDER BY hour;
```

Filter on the partition columns: a filter on `time_received_ns` alone still
reads every file. On a very large tree, narrowing the glob to the day,
`flows/date=2026-08-27/**/*.parquet`, also spares listing the rest.
