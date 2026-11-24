# Collector

The RustFlow collector receives NetFlow, IPFIX, and sFlow traffic over UDP or reads flow packets from a PCAP file.

## Network Input

`--input` names the flow protocol and the UDP address to receive it on:

```bash
rustflow collect --input netflow://:9995
```

The `netflow` type handles:

- NetFlow v5
- NetFlow v9
- IPFIX

The protocol version is detected automatically from the received packets.

For sFlow:

```bash
rustflow collect --input sflow://:6343
```

Without a host, RustFlow listens on all interfaces (`0.0.0.0`). Give one to
bind a specific address, with an IPv6 address in brackets:

```bash
rustflow collect --input netflow://192.0.2.10:9995
rustflow collect --input "sflow://[2001:db8::10]:6343"
```

### Several inputs

`--input` can be repeated, so one collector receives NetFlow and sFlow at the
same time:

```bash
rustflow collect \
  --input netflow://:9995 \
  --input sflow://:6343 \
  -f common
```

Each input decodes on its own thread and all of them feed the same output,
so the common format is the natural choice. With `--format raw`, NetFlow and
sFlow records are interleaved in one stream and are told apart only by their
fields.

See [Supported Protocols](protocols.md) for protocol support and references.

## PCAP Input

Instead of listening on a UDP socket, flows can be read from a PCAP file. The
`+pcap` suffix on the protocol marks a capture, and the rest of the URL is its
path, so an absolute path starts with three slashes:

```bash
rustflow collect --input netflow+pcap://capture.pcap
rustflow collect --input sflow+pcap:///var/captures/sflow.pcap
```

A capture can be combined with sockets; it is read on its own thread while
they listen.

## Output

By default, the collector writes the original protocol-specific flow structure as NDJSON to stdout.

Use `--format common` to normalize flows into the common flow schema:

```bash
rustflow collect \
  --input netflow://:9995 \
  --format common
```

For output formats, the common flow schema, Parquet, file rotation, and partitioning, see [Output](output.md).

## Custom Information Elements

Custom IPFIX Information Element mappings can be loaded from a CSV file using `--ie-mapping`:

```bash
rustflow collect \
  --input netflow://:4739 \
  --ie-mapping ie-mapping.csv
```

This can be used for enterprise-specific or vendor-specific Information Elements that are not part of the built-in mappings.

IPFIX exporters can also describe their own elements in type records ([RFC 5610](https://datatracker.ietf.org/doc/html/rfc5610)).
RustFlow uses a type record for an element that neither the built-in mappings nor `--ie-mapping` define, for the exporter and observation domain that sent it.
Elements described differently by two type records stay undecoded.

## Extra Fields

The common flow has a fixed set of fields. `--extra-field NAME=ELEMENT` adds a column named
`NAME` holding an element of every NetFlow v9 and IPFIX data record, for elements the common
flow does not keep. Repeat it for several fields:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  --extra-field direction=flowDirection \
  --extra-field vrf=ingressVRFID \
  --extra-field app=9/12235
```

`ELEMENT` is an element name, an ID (`61`), or `enterprise/ID` (`9/12235`). It must be an IANA
element or one from `--ie-mapping`, whose data type sets the column's type. `@NUMBER` after it,
as in `vrf=ingressVRFID@1000`, gives the field its [protobuf field number](output.md#protobuf).


| Element data type                       | Column                                          |
| --------------------------------------- | ----------------------------------------------- |
| unsigned integers                       | uint64                                          |
| signed integers                         | int64                                           |
| float32, float64                        | float64                                         |
| boolean                                 | boolean                                         |
| dateTimeSeconds ... dateTimeNanoseconds | timestamp, as nanoseconds like the flow's times |
| IPv4 and IPv6 addresses, MAC addresses  | string, in their usual notation                 |
| string                                  | string                                          |
| octetArray                              | string, in hex                                  |

In protobuf, addresses, MAC addresses and octet arrays are `bytes`, like the flow's own
addresses.

Lists and unsigned256 cannot be columns. A record without the element leaves its column empty,
and so do NetFlow v5 and sFlow flows. If a template lists an element twice, the first value is
used. The extra columns come after the flow's fields and before the enrichment fields, and a name
may not repeat any other column's. `--extra-field` requires `--format common`.

## Selecting Fields

`--fields` writes only the listed columns. A name is a common flow field, an extra field or an
enrichment output:

```bash
rustflow collect \
  --input netflow://:9995 \
  -f common \
  -s csv \
  --extra-field direction=flowDirection \
  --fields time_received_ns,src_addr,dst_addr,bytes,packets,direction
```

The columns are written in the order of the list. In protobuf the fields left out are unset, and
the numbers of the others do not change. An enrichment lookup can still use a flow field that is
not written as its key. `--fields` requires `--format common`.

## Template Cache

NetFlow v9 and IPFIX use templates to describe the fields contained in data records.

RustFlow caches received templates for subsequent data records.

The template cache timeout can be configured with `--template-timeout`:

```bash
rustflow collect \
  --input netflow://:4739 \
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
  --input netflow://:4739 \
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
  --input netflow://:9995 \
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
  --input netflow://:9995 \
  --metrics-host 127.0.0.1 \
  --metrics-port 9091
```

## CLI Options

Run the following command for the complete list of collector options:

```bash
rustflow collect --help
```
