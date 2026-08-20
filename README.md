# RustFlow

<div align="center">
  <img src="logo-white-bg.png" width="500" />
</div>

&nbsp;
&nbsp;

**RustFlow** is a high-performance flow collector written in Rust, with support for **NetFlow v5/v9, IPFIX, and sFlow v5**.

It can collect flows from the network or PCAP files, normalize them into a common schema, enrich them with external data, and export them as **NDJSON, CSV, or Parquet**.

## Features

- NetFlow v5 and v9
- IPFIX
- sFlow v5
- Network and PCAP input
- Raw or normalized flow output
- NDJSON, CSV, and Parquet serialization
- File rotation and time-based partitioning
- Flow enrichment using CSV or MaxMind databases
- Prometheus metrics
- IPFIX traffic generator
- Linux IPFIX exporter

## Installation

### crates.io

```bash
cargo install rustflow_cli
```

```bash
rustflow --version
```

Prebuilt static Linux binaries are also available from the [releases](https://github.com/meirdev/rustflow/releases) page.

## Quick Start

Collect NetFlow/IPFIX traffic:

```bash
rustflow collect -t netflow -p 9995
```

Collect sFlow:

```bash
rustflow collect -t sflow -p 6343
```

Write normalized flows to Parquet:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  -s parquet \
  -o flows.parquet
```

Read flows from a PCAP file:

```bash
rustflow collect -t netflow --pcap capture.pcap
```

## Commands

| Command             | Description                                    |
| ------------------- | ---------------------------------------------- |
| `rustflow collect`  | Collect NetFlow, IPFIX, or sFlow traffic       |
| `rustflow export`   | Capture network traffic and export it as IPFIX |
| `rustflow generate` | Generate synthetic IPFIX traffic               |

Run:

```bash
rustflow <command> --help
```

for the complete CLI options.

## Documentation

- [Collector](./docs/collector.md)
- [Output formats and rotation](./docs/output.md)
- [Flow enrichment](./docs/enrichment.md)
- [IPFIX exporter](./docs/exporter.md)
- [IPFIX traffic generator](./docs/generator.md)
- [Production deployment](./docs/deployment.md)
- [Protocol references](./docs/protocols.md)
- [Alternatives](./docs/alternatives.md)

## License

BSD 3-Clause
