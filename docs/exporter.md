# Exporter

RustFlow can capture packets from a network interface, aggregate them into flows, and export them as IPFIX to a collector.

> The exporter is currently supported on Linux.

## Basic Usage

By default, the exporter captures from the loopback interface and sends IPFIX to `127.0.0.1:4739`.

```bash
rustflow export
```

To capture from a specific interface:

```bash
rustflow export -i eth0
```

To send flows to a remote collector:

```bash
rustflow export \
  -i eth0 \
  -H 192.0.2.10 \
  -p 4739
```

## Observation Domain

The IPFIX observation domain ID can be configured with `--observation-domain-id`.

```bash
rustflow export \
  -i eth0 \
  --observation-domain-id 100
```

The default observation domain ID is `1`.

## Flow Timeouts

The exporter uses active and inactive timeouts to determine when flows are exported.

### Active Timeout

`--active-timeout` controls how long an active flow can remain in the flow table before it is exported.

The default is `60` seconds.

```bash
rustflow export \
  -i eth0 \
  --active-timeout 120
```

### Inactive Timeout

`--inactive-timeout` controls how long an inactive flow remains in the flow table before it is exported.

The default is `15` seconds.

```bash
rustflow export \
  -i eth0 \
  --inactive-timeout 30
```

## Template Refresh

IPFIX templates are periodically re-exported using `--template-refresh-rate`.

The default refresh interval is `300` seconds.

```bash
rustflow export \
  -i eth0 \
  --template-refresh-rate 60
```

## Sampling

Packet sampling can be configured using `--sampling-packet-interval`.

The default value is `1`, which processes every packet.

For example, to sample one out of every 100 packets:

```bash
rustflow export \
  -i eth0 \
  --sampling-packet-interval 100
```

## Promiscuous Mode

Use `--promiscuous` to enable promiscuous mode on the capture interface:

```bash
rustflow export \
  -i eth0 \
  --promiscuous
```

## Permissions

Capturing packets from a network interface requires sufficient privileges.

The exporter can be run as root:

```bash
sudo rustflow export -i eth0
```

Alternatively, appropriate Linux capabilities can be granted to the RustFlow binary.

## CLI Options

Run:

```bash
rustflow export --help
```

for the complete list of exporter options.
