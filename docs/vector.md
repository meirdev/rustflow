# Vector integration

[Vector](https://vector.dev) can read RustFlow's protobuf output directly and forward it to
any of its sinks.

This page walks through a complete pipeline: RustFlow collects NetFlow/IPFIX,
Vector decodes the protobuf stream, and ClickHouse stores the flows.

**Vector 0.58.0 or later is required.**

## Descriptor file

Vector decodes protobuf dynamically, so it needs a compiled `FileDescriptorSet` rather than
the `.proto` source. Generate one from
[`rustflow.proto`](../crates/rustflow_collect/proto/rustflow.proto) with `protoc`:

```bash
protoc -I crates/rustflow_collect/proto \
       -o rustflow.desc \
       crates/rustflow_collect/proto/rustflow.proto
```

If `protoc` is not installed, the same compiler ships inside `grpcio-tools` and can be run
without installing anything system-wide:

```bash
uvx --from grpcio-tools python -m grpc_tools.protoc \
    -I crates/rustflow_collect/proto \
    -o rustflow.desc \
    crates/rustflow_collect/proto/rustflow.proto
```

Install it where Vector can read it:

```bash
sudo mkdir -p /etc/vector
sudo cp rustflow.desc /etc/vector/
```

## ClickHouse table

This example stores the ten most common fields:

```sql
CREATE TABLE flows
(
    time_received    DateTime64(9),
    sampling_rate    UInt32,
    sampler_address  String,
    bytes            UInt64,
    packets          UInt64,
    src_addr         String,
    dst_addr         String,
    src_port         UInt16,
    dst_port         UInt16,
    proto            UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(time_received)
ORDER BY (time_received, src_addr, dst_addr);
```

_Addresses are stored as `String` because the pipeline converts them to text. To keep them
binary instead, use ClickHouse's `IPv6` type and drop the `ip_ntop` calls below._

## Vector configuration

`/etc/vector/vector.yaml`:

```yaml
sources:
  rustflow:
    type: exec
    mode: streaming
    command:
      - rustflow
      - collect
      - -t
      - netflow
      - -p
      - "9995"
      - -f
      - common
      - -s
      - protobuf
    include_stderr: false
    framing:
      method: varint_length_delimited
    decoding:
      codec: protobuf
      protobuf:
        desc_file: /etc/vector/rustflow.desc
        message_type: rustflow.CommonFlow

transforms:
  flows:
    type: remap
    inputs:
      - rustflow
    source: |
      ts = to_int(.time_received_ns) ?? 0

      sampler = ip_ntop(.sampler_address) ?? ""
      src = ip_ntop(.src_addr) ?? ""
      dst = ip_ntop(.dst_addr) ?? ""

      . = {
        "time_received":   from_unix_timestamp(ts, unit: "nanoseconds") ?? now(),
        "sampling_rate":   to_int(.sampling_rate) ?? 0,
        "sampler_address": sampler,
        "bytes":           to_int(.bytes) ?? 0,
        "packets":         to_int(.packets) ?? 0,
        "src_addr":        src,
        "dst_addr":        dst,
        "src_port":        to_int(.src_port) ?? 0,
        "dst_port":        to_int(.dst_port) ?? 0,
        "proto":           to_int(.proto) ?? 0,
      }

sinks:
  clickhouse:
    type: clickhouse
    inputs:
      - flows
    endpoint: http://localhost:8123
    database: default
    table: flows
    date_time_best_effort: true
    batch:
      timeout_secs: 5
```

## Running it

```bash
vector --config /etc/vector/vector.yaml
```

Send flows to port 9995 and confirm they land:

```sql
SELECT time_received, src_addr, dst_addr, src_port, dst_port, proto, bytes, packets
FROM flows
ORDER BY time_received DESC
LIMIT 10;
```
