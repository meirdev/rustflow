# RustFlow

<div align="center">
  <img src="logo-white-bg.png" width="500" />
</div>

&nbsp;
&nbsp;

<div align="center">
  <strong>RustFlow</strong> is a high-performance, modern flow collector written in Rust.
</div>

## Comparison

| Project                                          | Language | License      |
| ------------------------------------------------ | -------- | ------------ |
| [RustFlow](https://github.com/meirdev/rustflow)  | Rust     | BSD 3-Clause |
| [GoFlow2](https://github.com/netsampler/goflow2) | Go       | BSD 3-Clause |
| [vflow](https://github.com/Edgio/vflow)          | Go       | Apache-2.0   |
| [akvorado](https://github.com/akvorado/akvorado) | Go       | AGPL-3.0     |
| [ipfixcol2](https://github.com/CESNET/ipfixcol2) | C++      | GPL-2.0      |
| [nfdump](https://github.com/phaag/nfdump)        | C        | BSD          |
| [pmacct](http://pmacct.net)                      | C        | GPL-2.0      |
| [CERT NetSA](https://tools.netsa.cert.org)       | C        | GPL-2.0      |

## Supported Protocols

- IPFIX
- NetFlow v9
- NetFlow v5
- sFlow v5

## Docs

Links to relevant RFCs and specifications for flow protocols.

### sFlow

- [sFlow Version 5](https://sflow.org/sflow_version_5.txt)
- [sFlow Data Structures](https://sflow.org/SFLOW-STRUCTS5.txt)
- [InMon Corporation's sFlow: A Method for Monitoring Traffic in Switched and Routed Networks](https://sflow.org/rfc3176.txt)

### IPFIX

- [Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information](https://www.rfc-editor.org/rfc/rfc7011.html)
- [IP Flow Information Export (IPFIX) Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
- [Export of Structured Data in IP Flow Information Export (IPFIX)](https://www.rfc-editor.org/rfc/rfc6313.html)
- [Textual Representation of IP Flow Information Export (IPFIX) Abstract Data Types](https://www.rfc-editor.org/rfc/rfc7373.html)

### Netflow

- [NetFlow Export Datagram Formats](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.pdf)

## Collector Usage

The `rustflow_collector` binary collects flow data from network devices or pcap files.

### Basic Usage

```bash
# Collect NetFlow/IPFIX on UDP port 9995
rustflow_collector -t netflow -p 9995

# Collect sFlow on UDP port 6343
rustflow_collector -t sflow -p 6343

# Read from a pcap file
rustflow_collector -t netflow --pcap capture.pcap
```

### Output Formats

By default, the collector outputs raw protocol data as NDJSON (newline-delimited JSON, one object per line). Use `-f common` to normalize flows to a common format:

```bash
# Output normalized common flow format
rustflow_collector -t netflow -p 9995 -f common

# Output as CSV (requires common format)
rustflow_collector -t netflow -p 9995 -f common -s csv

# Output as Snappy-compressed Parquet (requires common format and -o)
rustflow_collector -t netflow -p 9995 -f common -s parquet -o flows.parquet

# Write to a single file instead of stdout
rustflow_collector -t netflow -p 9995 -f common -o flows.ndjson
```

| Serialization (`-s`) | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| `ndjson` (default)   | Newline-delimited JSON, one object per line. Works with `raw` and `common` |
| `csv`                | CSV with a header row. Requires `-f common`                                |
| `parquet`            | Apache Parquet with Snappy compression. Requires `-f common` and `-o`      |
| `discard`            | Decode and count flows (metrics only), write nothing. For load testing     |

**Parquet column types:** flow fields keep their native widths (`UInt8`/`UInt16`/`UInt32`/`UInt64`), the `time_*_ns` fields are written as `TIMESTAMP(NANOS, UTC)`, and IP and MAC addresses are written as fixed-size binary — 16 bytes for addresses (IPv4 is stored in its IPv4-mapped IPv6 form) and 6 bytes for MACs. Enrichment fields are appended as string columns.

### Output File Rotation

`--output` is a **single file** on its own. Add `--interval` and it becomes the **root directory** of a rotated tree, with one file per interval written into it:

```bash
# One file, never rotated
rustflow_collector -t netflow -p 9995 -f common -o flows.ndjson

# A new file every hour, all of them directly under ./flows
rustflow_collector -t netflow -p 9995 -f common -s parquet -o flows -i 1h

# A new file every 5 minutes, partitioned by day/hour/5-minute bucket
rustflow_collector -t netflow -p 9995 -f common -s parquet -o /data/flows -i 5m -l 3
```

Use `--level` (`-l`) to choose how deeply the output directory is partitioned by the interval's start time:

| Level         | Layout                    | Example                                           |
| ------------- | ------------------------- | ------------------------------------------------- |
| `0` (default) | `<output>/`               | `flows/flows-20240102T150500Z.parquet`            |
| `1`           | `<output>/%Y/%m/%d/`      | `flows/2024/01/02/flows-...parquet`               |
| `2`           | `<output>/%Y/%m/%d/%H/`   | `flows/2024/01/02/15/flows-...parquet`            |
| `3`           | `<output>/%Y/%m/%d/%H/%M` | `flows/2024/01/02/15/05/flows-...parquet` (5 min) |

File names are `<prefix>-<interval start>.<ext>`, where the prefix defaults to `flows` (set it with `--prefix` so several collectors can share one output tree) and the extension follows `--serialization` (`.ndjson`, `.csv` or `.parquet`). Missing directories are created as needed.

Interval windows are aligned to the epoch, so `-i 1h` rotates at the top of every hour. Rotation happens when the first flow of a new window arrives, so idle windows produce no files. `--level` and `--prefix` require `--interval`, since without it there is only one file.

### Flow Enrichment

Enrich flows with additional data using prefix matching. Supports CSV files and MaxMind DB (`.mmdb`) files:

```bash
# Enrich destination addresses with ASN and organization info from a CSV file
rustflow_collector -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org"

# Enrich with GeoIP data from a MaxMind DB file (use dotted paths for nested fields)
rustflow_collector -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-City.mmdb,key=src_addr,fields=country.iso_code:src_country;city.names.en:src_city"

# Multiple enrichments with auto-reload
rustflow_collector -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org,reload=30s" \
  --enrich "type=prefix_lookup,source=GeoLite2-Country.mmdb,key=dst_addr,fields=country.iso_code:dst_country,reload=1h"
```

**Enrichment CSV format:**

```csv
prefix,asn,org
1.0.0.0/24,13335,CLOUDFLARENET
1.0.16.0/24,2519,VECTANT ARTERIA Networks Corporation
```

**MaxMind DB fields:** use dotted paths to navigate the record tree (e.g., `country.iso_code`, `city.names.en`, `location.latitude`). The source file format is detected by extension (`.mmdb` or `.csv`).

**Enrichment parameters:**

| Parameter | Description                                                                                                                                               |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`    | Lookup type (`prefix_lookup`)                                                                                                                             |
| `source`  | Path to CSV or MaxMind DB (`.mmdb`) file                                                                                                                  |
| `key`     | Flow field to match (`src_addr`, `dst_addr`, `next_hop`, `sampler_address`)                                                                               |
| `fields`  | Field mappings as `source:output_name` separated by `;`. For CSV, source is the column name. For MMDB, source is a dotted path (e.g., `country.iso_code`) |
| `reload`  | Optional auto-reload interval (e.g., `10s`, `1m`, `1h`)                                                                                                   |

### Custom IE Mappings

Load custom Information Element definitions for IPFIX/NetFlow v9:

```bash
rustflow_collector -t netflow -p 9995 --ie-mapping custom_ies.csv
```

### Shutdown

On `SIGINT`/`SIGTERM` the collector stops reading the socket, writes out every
flow it has already decoded, finalizes the output file (Parquet needs its footer
to be readable), and exits. A second signal forces an immediate exit.

### Prometheus Metrics

When listening on a socket, metrics are exposed on port 9090 by default:

```bash
# Custom metrics endpoint
rustflow_collector -t netflow -p 9995 --metrics-host 127.0.0.1 --metrics-port 9100
```

### All Options

```
rustflow_collector --help
```

## Exporter Usage

The `rustflow_exporter` binary captures network traffic and exports it as IPFIX to a collector.

### Basic Usage

```bash
# Capture on eth0 and export to collector at 192.168.1.100:4739
rustflow_exporter -i eth0 -H 192.168.1.100 -p 4739

# Capture on loopback interface (default)
rustflow_exporter -H 127.0.0.1 -p 4739
```

### Options

| Option                       | Description                                | Default     |
| ---------------------------- | ------------------------------------------ | ----------- |
| `-i, --interface`            | Network interface to capture from          | `lo`        |
| `-H, --collector-host`       | Collector host address                     | `127.0.0.1` |
| `-p, --collector-port`       | Collector port                             | `4739`      |
| `--observation-domain-id`    | Observation domain ID                      | `1`         |
| `--active-timeout`           | Active flow timeout in seconds             | `60`        |
| `--inactive-timeout`         | Inactive flow timeout in seconds           | `15`        |
| `--template-refresh-rate`    | Template refresh rate in seconds           | `300`       |
| `--sampling-packet-interval` | Sampling packet interval (1 = all packets) | `1`         |
| `--promiscuous`              | Enable promiscuous mode                    | disabled    |

### Examples

```bash
# Capture with promiscuous mode and custom timeouts
rustflow_exporter -i eth0 -H 10.0.0.1 -p 2055 --promiscuous \
  --active-timeout 120 --inactive-timeout 30

# Sample 1 out of every 100 packets
rustflow_exporter -i eth0 -H 10.0.0.1 -p 4739 --sampling-packet-interval 100

# Enable debug logging
RUST_LOG=debug rustflow_exporter -i eth0 -H 10.0.0.1 -p 4739
```

### All Options

```
rustflow_exporter --help
```

## Generator Usage

The `rustflow_generator` binary generates synthetic IPFIX flow data for testing collectors under load.

### Basic Usage

```bash
# Send to a specific collector
rustflow_generator -H 192.168.1.100 -p 9995

# Generate at 5000 packets per second with 20 flows per packet
rustflow_generator -H 10.0.0.1 -p 4739 -r 5000 -f 20

# Send exactly 1000 packets then stop
rustflow_generator -H 10.0.0.1 -p 4739 -n 1000
```

### Customizing Generated Flows

```bash
# Specify source and destination CIDR ranges
rustflow_generator -H 10.0.0.1 -p 4739 \
  --src_cidr 172.16.0.0/12 --dst_cidr 10.0.0.0/8

# Generate only TCP flows on well-known destination ports
rustflow_generator -H 10.0.0.1 -p 4739 \
  --protocols 6 --dst_port_range 80-443

# Generate TCP and UDP flows with custom source port range
rustflow_generator -H 10.0.0.1 -p 4739 \
  --protocols 6,17 --src_port_range 49152-65535

# Unlimited rate (as fast as possible)
rustflow_generator -H 10.0.0.1 -p 4739 -r 0
```

### Options

| Option                    | Description                                      | Default          |
| ------------------------- | ------------------------------------------------ | ---------------- |
| `-H, --host`              | Collector host address                           | `127.0.0.1`      |
| `-p, --port`              | Collector port                                   | `4739`           |
| `-r, --rate`              | Packets per second (0 = unlimited)               | `1000`           |
| `-f, --flows_per_packet`  | Number of flow records per packet                | `10`             |
| `-n, --count`             | Total packets to send (0 = infinite)             | `0`              |
| `--observation-domain-id` | Observation domain ID                            | `1`              |
| `--template-interval`     | Template refresh interval in seconds             | `30`             |
| `--src-cidr`              | Source IP address range (CIDR)                   | `10.0.0.0/8`     |
| `--dst-cidr`              | Destination IP address range (CIDR)              | `192.168.0.0/16` |
| `--protocols`             | Comma-separated protocol numbers (6=TCP, 17=UDP) | `6,17`           |
| `--src-port-range`        | Source port range                                | `1024-65535`     |
| `--dst-port-range`        | Destination port range                           | `1-1024`         |

### All Options

```
rustflow_generator --help
```
