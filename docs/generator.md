# Generator

RustFlow can generate synthetic IPFIX traffic and send it to a collector.

## Basic Usage

By default, the generator sends traffic to `127.0.0.1:4739` at `1000` packets per second, with `10` flows per packet.

```bash
rustflow generate
```

To send traffic to a remote collector:

```bash
rustflow generate \
  -H 192.0.2.10 \
  -p 4739
```

## Rate

Use `--rate` (`-r`) to control the number of IPFIX packets sent per second:

```bash
rustflow generate \
  --rate 5000
```

A value of `0` disables rate limiting.

## Flows per Packet

Use `--flows-per-packet` (`-f`) to control how many flow records are included in each IPFIX packet:

```bash
rustflow generate \
  --flows-per-packet 50
```

The default is `10`.

## Packet Count

Use `--count` (`-n`) to limit the total number of packets sent:

```bash
rustflow generate \
  --count 10000
```

The default is `0`, which sends packets continuously.

## Observation Domain

The IPFIX observation domain ID can be configured using `--observation-domain-id`:

```bash
rustflow generate \
  --observation-domain-id 100
```

The default is `1`.

## Template Refresh

Templates are periodically re-sent according to `--template-interval`.

The default interval is `30` seconds.

```bash
rustflow generate \
  --template-interval 60
```

## Address Ranges

Source and destination addresses are generated from configurable IPv4 or IPv6 CIDR ranges.
Both ranges must use the same address family because they share one IPFIX flow template.

The defaults are:

```text
Source:      10.0.0.0/8
Destination: 192.168.0.0/16
```

Use `--src-cidr` and `--dst-cidr` to change them:

```bash
rustflow generate \
  --src-cidr 172.16.0.0/12 \
  --dst-cidr 10.0.0.0/8
```

To generate IPv6 flows:

```bash
rustflow generate \
  --src-cidr 2001:db8:1::/48 \
  --dst-cidr 2001:db8:2::/48
```

## Protocols

Use `--protocols` to specify a comma-separated list of IP protocol numbers.

By default, RustFlow generates TCP and UDP traffic:

```text
6,17
```

For example, to generate only TCP flows:

```bash
rustflow generate \
  --protocols 6
```

Or TCP, UDP, and ICMP:

```bash
rustflow generate \
  --protocols 6,17,1
```

## Port Ranges

Source and destination ports can be generated from configurable ranges.

The defaults are:

```text
Source ports:      1024-65535
Destination ports: 1-1024
```

Use `--src-port-range` and `--dst-port-range` to change them:

```bash
rustflow generate \
  --src-port-range 30000-60000 \
  --dst-port-range 80-443
```

Ranges are inclusive.

## TCP Flags

Use `--tcp-flags` to specify a comma-separated list of TCP flag choices. For each
generated TCP flow, RustFlow randomly selects one entry from the list. Non-TCP
flows use a value of `0`.

Flag names are case-insensitive. Supported names are `fin`, `syn`, `rst`, `psh`,
`ack`, `urg`, `ece`, `cwr`, and `ns`. Numeric values can be used for combined
flags; for example, `18` represents SYN and ACK.

```bash
rustflow generate \
  --protocols 6 \
  --tcp-flags syn,ack,18
```

The default is `0`.

## Flow Data Ranges

Use `--octet-range` and `--packet-range` to control the octet and packet counts
reported by each generated flow. Both ranges are inclusive.

```bash
rustflow generate \
  --octet-range 1200-9000 \
  --packet-range 10-100
```

The default octet range is `64-65535`, and the default packet range is `1-99`.
These per-flow packet counts are separate from `--count`, which limits the total
number of IPFIX packets sent by the generator.

## Example

Generate 100,000 IPv6 IPFIX packets at 10,000 packets per second, with 20 flows
per packet and configurable flow data:

```bash
rustflow generate \
  -H 192.0.2.10 \
  -p 4739 \
  --rate 10000 \
  --flows-per-packet 20 \
  --count 100000 \
  --src-cidr 2001:db8:1::/48 \
  --dst-cidr 2001:db8:2::/48 \
  --protocols 6 \
  --tcp-flags syn,ack,18 \
  --octet-range 1200-9000 \
  --packet-range 10-100
```

## CLI Options

Run:

```bash
rustflow generate --help
```

for the complete list of generator options.
