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
