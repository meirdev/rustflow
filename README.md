# RustFlow

**RustFlow** is a high-performance, modern flow collector written in Rust.

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

By default, the collector outputs raw protocol data as JSON. Use `-f common` to normalize flows to a common format:

```bash
# Output normalized common flow format
rustflow_collector -t netflow -p 9995 -f common

# Output as CSV (requires common format)
rustflow_collector -t netflow -p 9995 -f common -s csv

# Write to file instead of stdout
rustflow_collector -t netflow -p 9995 -f common -o flows.json
```

### Flow Enrichment

Enrich flows with additional data from CSV lookup tables using prefix matching:

```bash
# Enrich destination addresses with ASN and organization info from asn.csv
rustflow_collector -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org"

# Multiple enrichments with auto-reload
rustflow_collector -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org,reload=30s" \
  --enrich "type=prefix_lookup,source=country.csv,key=dst_addr,fields=country_code:dst_country_code;country_name:dst_country_name,reload=30s"
```

**Enrichment CSV format:**

```csv
prefix,asn,org
1.0.0.0/24,13335,CLOUDFLARENET
1.0.16.0/24,2519,VECTANT ARTERIA Networks Corporation
```

**Enrichment parameters:**

| Parameter | Description |
|-----------|-------------|
| `type` | Lookup type (`prefix_lookup`) |
| `source` | Path to CSV file |
| `key` | Flow field to match (`src_addr`, `dst_addr`, `next_hop`, `sampler_address`) |
| `fields` | Field mappings as `csv_column:output_name` separated by `;` |
| `reload` | Optional auto-reload interval (e.g., `10s`, `1m`, `1h`) |

### Custom IE Mappings

Load custom Information Element definitions for IPFIX/NetFlow v9:

```bash
rustflow_collector -t netflow -p 9995 --ie-mapping custom_ies.csv
```

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
