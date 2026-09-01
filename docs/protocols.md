# Supported Protocols

RustFlow supports the following flow protocols:

| Protocol | Version |
| -------- | ------- |
| NetFlow  | v5      |
| NetFlow  | v9      |
| IPFIX    | v10     |
| PSAMP    | -       |
| sFlow    | v5      |

## NetFlow v5

- [NetFlow Version 5 Flow-Record Format](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)

## NetFlow v9

- [RFC 3954 — Cisco Systems NetFlow Services Export Version 9](https://datatracker.ietf.org/doc/html/rfc3954)

## IPFIX

**Note:** IPFIX collection is currently supported over UDP only.

- [RFC 7011 — Specification of the IP Flow Information Export (IPFIX) Protocol](https://datatracker.ietf.org/doc/html/rfc7011)
- [RFC 7012 — Information Model for IP Flow Information Export](https://datatracker.ietf.org/doc/html/rfc7012)
- [IANA IPFIX Information Elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

## PSAMP

PSAMP (Packet SAMPling) rides entirely on IPFIX: a Packet Report is an IPFIX
Data Record describing a single sampled packet, and the sampling
configuration arrives as Options Data Records (report interpretations).
RustFlow collects PSAMP on the same listener as IPFIX:

- Packet Reports convert to `CommonFlow` records with `packets = 1`,
  `selection_sequence_id` set, `time_flow_start_ns`/`time_flow_end_ns` taken
  from `observationTime*`, and the link/network/transport fields dissected
  from `dataLinkFrameSection` / `ipHeaderPacketSection` when present.
- Selector, Selection Sequence, and Selection Sequence Statistics report
  interpretations are tracked per exporter and observation domain; the
  effective `sampling_rate` of a Packet Report is resolved from its
  Selection Sequence, preferring the attained selection fraction from the
  statistics over the configured selector parameters.

References:

- [RFC 5476 — Packet Sampling (PSAMP) Protocol Specifications](https://datatracker.ietf.org/doc/html/rfc5476)
- [RFC 5477 — Information Model for Packet Sampling Exports](https://datatracker.ietf.org/doc/html/rfc5477)
- [RFC 5475 — Sampling and Filtering Techniques for IP Packet Selection](https://datatracker.ietf.org/doc/html/rfc5475)
- [IANA PSAMP Parameters](https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xhtml)

## sFlow v5

- [sFlow Version 5 Specification](https://sflow.org/sflow_version_5.txt)
