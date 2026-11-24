# Protocol conformance captures

Captures that check the NetFlow v5, NetFlow v9, IPFIX and sFlow v5 parsers
against the specifications, one capture per section or structure, and the
conversion of what they read to common flows.

```
conformance/                  the generator and the checker
fixtures/conformance/
  INDEX.md                    every case, the section it covers, what it checks
  netflow_v5/<case>.pcap      the capture
  netflow_v5/<case>.json      what a collector must make of it
  netflow_v9/  ipfix/  sflow_v5/
  vendors/<case>.pcap         how an exporter seen in the field departs from
  vendors/<case>.json         the common reading, rebuilt (see below)
```

`fixtures/conformance/INDEX.md` is the list of cases.

## Where the expected results come from

The expected result of a case is **written by hand from the specification,
next to the bytes it describes**. It is never recorded from rustflow's
output, so it cannot inherit a parser's mistake.

In a case file every value is written once and used twice. `U(5009, 4)` is
the four bytes `00 00 13 91` in the capture and the number `5009` in the
expected record; `IP("192.0.2.12")` is four bytes and the string
`"192.0.2.12"`. The encoders (`wire.py`, `values.py`) follow the
specifications and import nothing from rustflow. Malformed cases are built
from raw bytes.

Two things guard against a mistake in the generator itself:

- **Wireshark reads every capture too.** A case lists Wireshark fields and
  the values they must take (`tshark` in the `.json`), and unless it says
  `"clean": false`, Wireshark must find nothing malformed in it. The
  captures and the expected values were written first; Wireshark then
  caught several wrong lengths in them.
- **The RFCs' own examples are cases**, value for value:
  `netflow_v9/s11_examples` (RFC 3954 section 11) and
  `ipfix/appendix_a_examples` (RFC 7011 appendix A).

The expected result has the shape of `rustflow collect --format raw`: one
JSON object per packet, in capture order, as `{"protocol": ..., "packet":
...}`. A datagram that must be discarded has no entry. NetFlow v9 and
IPFIX records are maps from IANA element names to values in their RFC 7373
text form (timestamps in UTC, without an offset), and a list is an array
of its values or records. The files are compared as JSON values, not as
text.

The shape is rustflow's, so a change to the raw output format means
updating the helpers that build it (`packet`, `message`, `datagram`,
`data` and the like in each module) and regenerating; the values and the
captures stay as they are.

## The flows

Every case also lists `flows`: the common flows `rustflow collect --format
common` must make of the capture, compared whole. They are not written by
hand but derived from the case's expected packets by `flows.py`, a model of
the conversion documented in [docs/output.md](../../docs/output.md):
which element or record fills which field, the era of a timestamp, which
sampling rate a record gets, and how a sampled packet header is read. The
model is written apart from rustflow and imports nothing from it, so a
disagreement is a bug in one of the two. A change to the conversion means
changing the model to match, which shows in the regenerated flows.

A case that rustflow is known not to satisfy carries a `deviation` note
saying why; it is reported as an expected failure, and as an error once it
starts passing.

## Running

```sh
python3 tests/conformance/check.py              # rustflow and Wireshark
python3 tests/conformance/check.py --captures   # Wireshark only
cd tests && uv run pytest test_conformance.py   # the same, under pytest
```

## Vendors and models

`vendors.py` holds cases for exporters seen in the field that read the
specification their own way, such as one that states its sampling rate
under another source ID than its data. A case rebuilds the exporter's
packets byte for byte where it matters, with documentation addresses and
names, never a capture from a real network. It is checked like any other
case; what such an exporter gets wrong mostly shows in its flows.

## Changing or adding a case

Edit the protocol's module (`netflow_v5.py`, `netflow_v9.py`, `ipfix.py`,
`sflow_v5.py`, or `vendors.py`), then regenerate and check the captures:

```sh
python3 tests/conformance/generate.py
python3 tests/conformance/check.py --captures
```

The generator is deterministic: it rewrites every capture, and a run with
no change to the cases changes no file.

## What is covered

| Specification | Sections |
| --- | --- |
| NetFlow v5 (Cisco, NetFlow Export Datagram Format) | header, flow record |
| RFC 3954, NetFlow v9 | 4, 5.1, 5.2, 5.3, 6.1, 6.2, 7, 8, 9, 11 |
| RFC 7011, IPFIX | 3.1, 3.2, 3.3.1, 3.3.2, 3.4.1, 3.4.2, 3.4.3, 4.1 to 4.4, 5.1, 5.2, 6.1.1 to 6.1.10, 6.2, 7, 8, 8.1, 8.4, 9, 9.1, appendix A |
| RFC 7012, IPFIX information model | 4 (reserved element 0) |
| RFC 6313, IPFIX structured data | 4.5.1, 4.5.2, 4.5.3, 5.2, 5.3 |
| RFC 5610, IPFIX type information | 3, 3.8, 3.9, 3.10 |
| RFC 7373, IPFIX text types | 4.4 (float values); the text form of every value |
| sFlow Version 5 | section 5, every structure the parser reads, extended structures |
| sFlow Dropped Packet Notification Structures | section 2 |

Left out, because a capture cannot show them:

- Template expiry (RFC 3954 section 9, RFC 7011 sections 8.4 and 9.3): it
  runs on the collector's clock, not on capture time.
- SCTP and TCP transport (RFC 7011 sections 8.2, 8.3, 9.2 and 10): the
  collector reads UDP.

Cases marked "(robustness)" in the index cover what the specification
leaves open, such as a NetFlow v9 FlowSet that runs past its datagram.
Their expected results state rustflow's documented behaviour rather than
a requirement.
