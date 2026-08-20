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

Source and destination addresses are generated from configurable CIDR ranges.

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

## Example

Generate 100,000 IPFIX packets at 10,000 packets per second, with 20 flows per packet:

```bash
rustflow generate \
  -H 192.0.2.10 \
  -p 4739 \
  --rate 10000 \
  --flows-per-packet 20 \
  --count 100000
```

## CLI Options

Run:

```bash
rustflow generate --help
```

for the complete list of generator options.
