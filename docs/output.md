# Output

RustFlow supports two flow representations:

- **Raw** - preserves the original protocol-specific flow structure.
- **Common** - normalizes NetFlow, IPFIX, and sFlow into a common schema.

The common format can be serialized as **NDJSON, CSV, Protobuf, or Parquet**, or discarded entirely for load testing.

## Common Flow

The common flow format provides a consistent schema across the supported flow protocols.

| Field                   | Type      | Optional | Description                            |
| ----------------------- | --------- | -------- | -------------------------------------- |
| `flow_type`             | string    | No       | Source flow protocol/type              |
| `time_received_ns`      | timestamp | Yes      | Time the flow was received             |
| `sequence_num`          | uint32    | No       | Export packet sequence number          |
| `sampling_rate`         | uint32    | Yes      | Sampling rate reported by the exporter |
| `sampler_address`       | string    | Yes      | Address of the flow exporter/sampler   |
| `time_flow_start_ns`    | timestamp | Yes      | Flow start time                        |
| `time_flow_end_ns`      | timestamp | Yes      | Flow end time                          |
| `bytes`                 | uint64    | No       | Number of bytes in the flow            |
| `packets`               | uint64    | No       | Number of packets in the flow          |
| `src_addr`              | string    | Yes      | Source IPv4 or IPv6 address            |
| `dst_addr`              | string    | Yes      | Destination IPv4 or IPv6 address       |
| `src_mac`               | string    | Yes      | Source MAC address                     |
| `dst_mac`               | string    | Yes      | Destination MAC address                |
| `etype`                 | uint16    | Yes      | Ethernet EtherType                     |
| `proto`                 | uint8     | Yes      | IP protocol number                     |
| `src_port`              | uint16    | Yes      | Source transport port                  |
| `dst_port`              | uint16    | Yes      | Destination transport port             |
| `in_if`                 | uint32    | Yes      | Input interface index                  |
| `out_if`                | uint32    | Yes      | Output interface index                 |
| `ip_tos`                | uint8     | Yes      | IP Type of Service / traffic class     |
| `ip_ttl`                | uint8     | Yes      | IP TTL / hop limit                     |
| `tcp_flags`             | uint8     | Yes      | TCP flags bitmask                      |
| `icmp_type`             | uint8     | Yes      | ICMP type                              |
| `icmp_code`             | uint8     | Yes      | ICMP code                              |
| `ipv6_flow_label`       | uint32    | Yes      | IPv6 flow label                        |
| `fragment_id`           | uint32    | Yes      | IP fragment identifier                 |
| `fragment_offset`       | uint16    | Yes      | IP fragment offset                     |
| `src_as`                | uint32    | Yes      | Source autonomous system number        |
| `dst_as`                | uint32    | Yes      | Destination autonomous system number   |
| `next_hop`              | string    | Yes      | IP next-hop address                    |
| `src_net`               | uint8     | Yes      | Source prefix length                   |
| `dst_net`               | uint8     | Yes      | Destination prefix length              |
| `bgp_next_hop`          | string    | Yes      | BGP next-hop address                   |
| `src_vlan`              | uint16    | Yes      | Source VLAN ID                         |
| `dst_vlan`              | uint16    | Yes      | Destination VLAN ID                    |
| `observation_domain_id` | uint32    | Yes      | IPFIX observation domain ID            |
| `template_id`           | uint16    | Yes      | NetFlow v9 / IPFIX template ID         |

Fields that are unavailable in the original flow record are left unset.

`flow_type` is one of `NETFLOW_V5`, `NETFLOW_V9`, `IPFIX`, or `SFLOW_V5`.

## NDJSON

Each flow is serialized as a single JSON object per line.

Optional fields that do not have a value are omitted.

```json
{
  "flow_type": "IPFIX",
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

CSV output uses a fixed set of columns matching the common flow schema.

```text
flow_type,time_received_ns,sequence_num,sampling_rate,sampler_address,...,template_id
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
  -t netflow \
  -p 9995 \
  -f common \
  -s ndjson \
  -o flows.ndjson
```

Without `--interval`, `--output` refers to a single file.

For Parquet output, `--format common` and `--output` are required:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
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
  -t netflow \
  -p 9995 \
  -f common \
  -s protobuf \
  -o flows.pb
```

Protobuf messages are **length-delimited**: each message is prefixed with its size as a varint.

## Discard

`-s discard` decodes and counts flows without writing them anywhere. Flows are still
parsed and reported through the Prometheus metrics, which makes it useful for measuring
ingest throughput without paying for serialization or disk:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  -s discard
```

## File Rotation

Use `--interval` (`-i`) to start a new output file at a fixed interval.

When `--interval` is used, `--output` refers to the root directory of the output tree instead of a single file.

For example:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  -s parquet \
  -o flows \
  --interval 10m
```

This creates a new output file every 10 minutes.

A custom file name prefix can be specified with `--prefix`:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
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

## Partitioning

Rotated output can be organized into time-based directory partitions using `--level` (`-l`).

| Level | Directory layout                                 |
| ----- | ------------------------------------------------ |
| `0`   | Flat output directory                            |
| `1`   | `%Y/%m/%d`                                       |
| `2`   | `%Y/%m/%d/%H`                                    |
| `3`   | `%Y/%m/%d/%H` with an additional 5-minute bucket |

`--level` requires `--interval`.

For example:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
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
