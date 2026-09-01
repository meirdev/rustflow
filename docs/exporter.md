# Exporter

RustFlow can capture packets from a network interface, aggregate them into flows, and export them as IPFIX to a collector.

The exporter runs on Linux, macOS, and Windows. Packet capture goes through
one of two backends, selected with `--capture`:

| Backend | Platforms | Notes |
| ------- | --------- | ----- |
| `af-packet` | Linux | `AF_PACKET` mmap ring (TPACKET_V3, block-oriented); no external dependencies. The Linux default. |
| `pcap` | Linux, macOS, Windows | libpcap (bundled with macOS, `libpcap-dev` on Linux) or [Npcap](https://npcap.com/) on Windows. The default outside Linux. |

`--capture auto` (the default) picks `af-packet` on Linux and `pcap` elsewhere.

The `pcap` backend is a cargo feature of `rustflow_export` (enabled
automatically when building the CLI for macOS or Windows, off by default on
Linux so builds don't require libpcap). To use it on Linux, build with
`--features rustflow_export/pcap`.

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

## Sampling Algorithms

The exporter implements the four content-independent sampling schemes of
[RFC 5475](https://datatracker.ietf.org/doc/html/rfc5475), selected with
`--sampling-algorithm`:

| Algorithm | selectorAlgorithm | Parameters |
| --------- | ----------------- | ---------- |
| `count-based` (default) | 1 | `--sampling-packet-interval N` — select 1 of every N packets |
| `time-based` | 2 | `--sampling-time-interval` / `--sampling-time-space` — microseconds selecting / skipping per cycle |
| `n-out-of-n` | 3 | `--sampling-size n` / `--sampling-population N` — exactly n random picks per N packets |
| `probabilistic` | 4 | `--sampling-probability p` — each packet selected independently with probability p ∈ (0, 1] |

```bash
rustflow export -i eth0 --mode packets \
  --sampling-algorithm probabilistic --sampling-probability 0.01
```

In `--mode packets` the Selector Report Interpretation carries the exact
algorithm and its parameters. In `--mode flows` the legacy sampling options
record carries the equivalent 1-in-N rate (population/size for n-out-of-n,
round(1/p) for probabilistic); time-based sampling has no packet-count rate,
so no rate is exported and collectors cannot scale flow volumes.

## PSAMP Packet Reports

By default the exporter aggregates packets into flows. With `--mode packets`
it acts as a PSAMP Device ([RFC 5476](https://datatracker.ietf.org/doc/html/rfc5476))
instead, exporting one Packet Report per selected packet:

```bash
rustflow export \
  -i eth0 \
  --mode packets \
  --sampling-packet-interval 100 \
  --section-length 128
```

Each Packet Report carries the `selectionSequenceId`, the observation
timestamp in milliseconds, the original frame length (`dataLinkFrameSize`),
and the first `--section-length` bytes of the frame
(`dataLinkFrameSection`, variable-length encoded). Alongside them the
exporter sends the RFC 5476 report interpretations: a Selector Report
(systematic count-based sampling, `samplingPacketInterval`/`samplingPacketSpace`),
a Selection Sequence Report, and — every `--stats-interval` seconds — a
Selection Sequence Statistics Report with packets observed/selected, from
which a collector computes the attained sampling fraction.

`rustflow collect` decodes all of this: packet reports become `CommonFlow`
records with `packets = 1`, `selection_sequence_id` set, and the
`sampling_rate` resolved from the selection sequence.

In `--mode flows` the wire format is unchanged from previous releases (flow
records plus the legacy sampling options record).

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

On macOS, access to the `/dev/bpf*` devices is required (run as root, or use
the `access_bpf` group installed by Wireshark's ChmodBPF helper). On Windows,
install [Npcap](https://npcap.com/) and run from an elevated prompt unless
Npcap was installed with unprivileged capture enabled.

## CLI Options

Run:

```bash
rustflow export --help
```

for the complete list of exporter options.
