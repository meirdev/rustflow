# Collector

The RustFlow collector receives NetFlow, IPFIX, and sFlow traffic over UDP or reads flow packets from a PCAP file.

## Network Input

`--listen` names the flow protocol and the UDP address to receive it on:

```bash
rustflow collect --listen netflow://:9995
```

The `netflow` type handles:

- NetFlow v5
- NetFlow v9
- IPFIX

The protocol version is detected automatically from the received packets.

For sFlow:

```bash
rustflow collect --listen sflow://:6343
```

Without a host, RustFlow listens on all interfaces (`0.0.0.0`). Give one to
bind a specific address, with an IPv6 address in brackets:

```bash
rustflow collect --listen netflow://192.0.2.10:9995
rustflow collect --listen "sflow://[2001:db8::10]:6343"
```

### Several listeners

`--listen` can be repeated, so one collector receives NetFlow and sFlow at the
same time:

```bash
rustflow collect \
  --listen netflow://:9995 \
  --listen sflow://:6343 \
  -f common
```

Each listener decodes on its own thread and all of them feed the same output,
so the common format is the natural choice. With `--format raw`, NetFlow and
sFlow records are interleaved in one stream and are told apart only by their
fields.

See [Supported Protocols](protocols.md) for protocol support and references.

## PCAP Input

Instead of listening on a UDP socket, flows can be read from a PCAP file. The
URL names the protocol the capture holds:

```bash
rustflow collect --pcap netflow://capture.pcap
```

`--pcap` cannot be used together with `--listen`.

## Output

By default, the collector writes the original protocol-specific flow structure as NDJSON to stdout.

Use `--format common` to normalize flows into the common flow schema:

```bash
rustflow collect \
  --listen netflow://:9995 \
  --format common
```

For output formats, the common flow schema, Parquet, file rotation, and partitioning, see [Output](output.md).

## Custom Information Elements

Custom IPFIX Information Element mappings can be loaded from a CSV file using `--ie-mapping`:

```bash
rustflow collect \
  --listen netflow://:4739 \
  --ie-mapping ie-mapping.csv
```

This can be used for enterprise-specific or vendor-specific Information Elements that are not part of the built-in mappings.

## Template Cache

NetFlow v9 and IPFIX use templates to describe the fields contained in data records.

RustFlow caches received templates for subsequent data records.

The template cache timeout can be configured with `--template-timeout`:

```bash
rustflow collect \
  --listen netflow://:4739 \
  --template-timeout 1200
```

The default timeout is `600` seconds.

## Receive Buffer

Datagrams queue in the socket receive buffer while the collector is busy, for
example during an output flush. Once the buffer is full the kernel drops new
datagrams silently, and NetFlow has no retransmission. The size can be
configured with `--recv-buffer` (bytes, default 4 MiB):

```bash
rustflow collect \
  --listen netflow://:4739 \
  --recv-buffer 16777216
```

The kernel caps the buffer at its own limit and the collector warns at startup
when the granted size is smaller than requested. On Linux the limit is
`net.core.rmem_max`:

```bash
sysctl -w net.core.rmem_max=16777216
```

Drops show up in the `drops` column of `/proc/net/udp` or in `ss -ulm`.

## Enrichment

Flows can be enriched with external data using `--enrich`.

Multiple enrichment configurations can be specified:

```bash
rustflow collect \
  --listen netflow://:9995 \
  -f common \
  --enrich "..." \
  --enrich "..."
```

See [Enrichment](enrichment.md) for configuration and examples.

## Prometheus Metrics

The collector exposes Prometheus metrics over HTTP, in the OpenMetrics text format.

By default, the metrics server listens on:

```text
0.0.0.0:9090
```

The address and port can be changed using `--metrics-host` and `--metrics-port`:

```bash
rustflow collect \
  --listen netflow://:9995 \
  --metrics-host 127.0.0.1 \
  --metrics-port 9091
```

## CLI Options

Run the following command for the complete list of collector options:

```bash
rustflow collect --help
```
