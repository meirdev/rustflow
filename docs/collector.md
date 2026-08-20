# Collector

The RustFlow collector receives NetFlow, IPFIX, and sFlow traffic over UDP or reads flow packets from a PCAP file.

## Network Input

Use `--flow-type` (`-t`) to select the flow protocol and `--port` (`-p`) to specify the UDP port:

```bash
rustflow collect -t netflow -p 9995
```

The `netflow` type handles:

- NetFlow v5
- NetFlow v9
- IPFIX

The protocol version is detected automatically from the received packets.

For sFlow:

```bash
rustflow collect -t sflow -p 6343
```

By default, RustFlow listens on all interfaces (`0.0.0.0`).

Use `--host` (`-H`) to bind to a specific address:

```bash
rustflow collect \
  -t netflow \
  -H 192.0.2.10 \
  -p 9995
```

See [Supported Protocols](protocols.md) for protocol support and references.

## PCAP Input

Instead of listening on a UDP socket, flows can be read from a PCAP file:

```bash
rustflow collect \
  -t netflow \
  --pcap capture.pcap
```

`--pcap` cannot be used together with `--host` or `--port`.

## Output

By default, the collector writes the original protocol-specific flow structure as NDJSON to stdout.

Use `--format common` to normalize flows into the common flow schema:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  --format common
```

For output formats, the common flow schema, Parquet, file rotation, and partitioning, see [Output](output.md).

## Custom Information Elements

Custom IPFIX Information Element mappings can be loaded from a CSV file using `--ie-mapping`:

```bash
rustflow collect \
  -t netflow \
  -p 4739 \
  --ie-mapping ie-mapping.csv
```

This can be used for enterprise-specific or vendor-specific Information Elements that are not part of the built-in mappings.

## Template Cache

NetFlow v9 and IPFIX use templates to describe the fields contained in data records.

RustFlow caches received templates for subsequent data records.

The template cache timeout can be configured with `--template-timeout`:

```bash
rustflow collect \
  -t netflow \
  -p 4739 \
  --template-timeout 1200
```

The default timeout is `600` seconds.

## Enrichment

Flows can be enriched with external data using `--enrich`.

Multiple enrichment configurations can be specified:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "..." \
  --enrich "..."
```

See [Enrichment](enrichment.md) for configuration and examples.

## Prometheus Metrics

The collector exposes Prometheus metrics over HTTP.

By default, the metrics server listens on:

```text
0.0.0.0:9090
```

The address and port can be changed using `--metrics-host` and `--metrics-port`:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  --metrics-host 127.0.0.1 \
  --metrics-port 9091
```

## CLI Options

Run the following command for the complete list of collector options:

```bash
rustflow collect --help
```
