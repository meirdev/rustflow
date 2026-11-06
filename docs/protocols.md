# Supported Protocols

RustFlow supports the following flow protocols:

| Protocol | Version |
| -------- | ------- |
| NetFlow  | v5      |
| NetFlow  | v9      |
| IPFIX    | v10     |
| sFlow    | v5      |

## NetFlow v5

- [NetFlow Version 5 Flow-Record Format](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)

## NetFlow v9

- [RFC 3954 — Cisco Systems NetFlow Services Export Version 9](https://datatracker.ietf.org/doc/html/rfc3954)

## IPFIX

**Note:** IPFIX collection is currently supported over UDP only.

- [RFC 7011 — Specification of the IP Flow Information Export (IPFIX) Protocol](https://datatracker.ietf.org/doc/html/rfc7011)
- [RFC 7012 — Information Model for IP Flow Information Export](https://datatracker.ietf.org/doc/html/rfc7012)
- [RFC 7013 — Guidelines for Authors and Reviewers of IPFIX Information Elements](https://datatracker.ietf.org/doc/html/rfc7013), for naming elements the registry does not know by their specifier
- [RFC 6313 — Export of Structured Data in IPFIX](https://datatracker.ietf.org/doc/html/rfc6313): basicList, subTemplateList and subTemplateMultiList
- [RFC 5610 — Exporting Type Information for IPFIX Information Elements](https://datatracker.ietf.org/doc/html/rfc5610)
- [RFC 5477 — Information Model for Packet Sampling Exports](https://datatracker.ietf.org/doc/html/rfc5477): packet sections are dissected into flow fields
- [RFC 7373 — Textual Representation of IP Flow Information Export (IPFIX) Abstract Data Types](https://datatracker.ietf.org/doc/html/rfc7373), the form of the raw output and of `Record::text`
- [IANA IPFIX Information Elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

## sFlow v5

- [sFlow Version 5 Specification](https://sflow.org/sflow_version_5.txt)
