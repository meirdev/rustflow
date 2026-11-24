"""IPFIX cases, by section of RFC 7011, with RFC 6313 (structured data)
and RFC 5610 (type information)."""

import struct
from datetime import datetime, timezone

import netflow_v5
import netflow_v9
from values import F32, F64, HEX, IP, MAC, STR, S, U, record
from wire import Case, Datagram, Pair, case, u16, u32, u8

VARIABLE = 65535
# The private enterprise number reserved for documentation (RFC 5612).
PEN = 32473

NAMES = {
    1: "octetDeltaCount",
    2: "packetDeltaCount",
    3: "deltaFlowCount",
    4: "protocolIdentifier",
    5: "ipClassOfService",
    6: "tcpControlBits",
    7: "sourceTransportPort",
    8: "sourceIPv4Address",
    10: "ingressInterface",
    11: "destinationTransportPort",
    12: "destinationIPv4Address",
    14: "egressInterface",
    15: "ipNextHopIPv4Address",
    16: "bgpSourceAsNumber",
    27: "sourceIPv6Address",
    28: "destinationIPv6Address",
    40: "exportedOctetTotalCount",
    41: "exportedMessageTotalCount",
    42: "exportedFlowRecordTotalCount",
    56: "sourceMacAddress",
    82: "interfaceName",
    83: "interfaceDescription",
    85: "octetTotalCount",
    86: "packetTotalCount",
    90: "mplsVpnRouteDistinguisher",
    130: "exporterIPv4Address",
    141: "lineCardId",
    143: "meteringProcessId",
    145: "templateId",
    149: "observationDomainId",
    150: "flowStartSeconds",
    151: "flowEndSeconds",
    152: "flowStartMilliseconds",
    154: "flowStartMicroseconds",
    156: "flowStartNanoseconds",
    158: "flowStartDeltaMicroseconds",
    159: "flowEndDeltaMicroseconds",
    164: "ignoredPacketTotalCount",
    165: "ignoredOctetTotalCount",
    166: "notSentFlowTotalCount",
    167: "notSentPacketTotalCount",
    168: "notSentOctetTotalCount",
    173: "flowKeyIndicator",
    276: "dataRecordsReliability",
    291: "basicList",
    292: "subTemplateList",
    293: "subTemplateMultiList",
    303: "informationElementId",
    311: "samplingProbability",
    322: "observationTimeSeconds",
    323: "observationTimeMilliseconds",
    339: "informationElementDataType",
    341: "informationElementName",
    344: "informationElementSemantics",
    346: "privateEnterpriseNumber",
    434: "mibObjectValueInteger",
}

# A field specifier is (element ID, length) or, for an enterprise-specific
# element, (element ID, length, enterprise number).
Spec = tuple


def name(spec: Spec) -> str:
    """The key an element is printed under: IANA's name, or for an element
    the collector has no definition of, its number as `(id)` or
    `(pen/id)`."""
    if len(spec) == 3:
        return f"{spec[2]}/{spec[0]}"
    return NAMES.get(spec[0], str(spec[0]))


def names(specs: list[Spec]) -> list[str]:
    return [name(spec) for spec in specs]


def spec_wire(spec: Spec) -> bytes:
    """Section 3.2: the top bit of the element ID says an enterprise number
    follows."""
    if len(spec) == 3:
        return u16(0x8000 | spec[0]) + u16(spec[1]) + u32(spec[2])
    return u16(spec[0]) + u16(spec[1])


def spec_text(spec: Spec) -> dict:
    text = {"information_element_id": spec[0], "field_length": spec[1]}
    if len(spec) == 3:
        text["enterprise_number"] = spec[2]
    return text


# List semantics (RFC 6313 section 4.4), by the name IANA's registry gives.
SEMANTICS = {0: "noneOf", 1: "exactlyOneOf", 2: "oneOrMoreOf", 3: "allOf", 4: "ordered", 0xFF: "undefined"}


def semantic_text(semantic: int):
    """A semantic IANA has not assigned prints as `unassigned`."""
    return SEMANTICS.get(semantic, {"unassigned": semantic})


def listed(semantic: int, spec: Spec, values: list) -> dict:
    """A basicList as printed: its semantic, its field specifier and its
    values (RFC 6313 section 4.5.1)."""
    return {"semantic": semantic_text(semantic), "field": spec_text(spec), "values": values}


def group(template_id: int, records: list | None = None, data: bytes | None = None) -> dict:
    """Records of a template as a list prints them, or for a template the
    collector does not have, the octets (RFC 6313 sections 4.5.2 and
    4.5.3)."""
    if data is not None:
        return {"template_id": template_id, "data": data.hex()}
    return {"template_id": template_id, "records": records}


def sub_listed(semantic: int, template_id: int, records: list | None = None, data: bytes | None = None) -> dict:
    """A subTemplateList as printed: its semantic and its records."""
    return {"semantic": semantic_text(semantic), **group(template_id, records, data)}


def multi_listed(semantic: int, groups: list[dict]) -> dict:
    """A subTemplateMultiList as printed: its semantic and its groups."""
    return {"semantic": semantic_text(semantic), "groups": groups}


def a_set(set_id: int, body: bytes, padding: bytes = b"") -> bytes:
    """Section 3.3: Set ID, Length (header and padding included), records,
    padding."""
    return u16(set_id) + u16(4 + len(body) + len(padding)) + body + padding


def template(template_id: int, specs: list[Spec]) -> Pair:
    """Section 3.4.1. With no fields, a withdrawal (section 8.1)."""
    wire = u16(template_id) + u16(len(specs)) + b"".join(map(spec_wire, specs))
    text = {"template_id": template_id, "fields": [spec_text(s) for s in specs]}
    return Pair(wire, text)


def templates(*records: Pair, padding: bytes = b"") -> Pair:
    wire = a_set(2, b"".join(r.wire for r in records), padding)
    return Pair(wire, {"type": "templates", "templates": [r.text for r in records]})


def options_template(template_id: int, scopes: list[Spec], options: list[Spec]) -> Pair:
    """Section 3.4.2.2: Field Count counts the scope fields too."""
    wire = u16(template_id) + u16(len(scopes) + len(options)) + u16(len(scopes))
    wire += b"".join(map(spec_wire, scopes + options))
    text = {
        "template_id": template_id,
        "scope_fields": [spec_text(s) for s in scopes],
        "option_fields": [spec_text(s) for s in options],
    }
    return Pair(wire, text)


def options_withdrawal(template_id: int) -> Pair:
    """Section 8.1: an options template withdrawal has no scope field
    count."""
    text = {"template_id": template_id, "scope_fields": [], "option_fields": []}
    return Pair(u16(template_id) + u16(0), text)


def options_templates(*records: Pair, padding: bytes = b"") -> Pair:
    wire = a_set(3, b"".join(r.wire for r in records), padding)
    return Pair(wire, {"type": "options_templates", "templates": [r.text for r in records]})


def data(
    template_id: int,
    keys: list[str],
    rows: list[list[Pair]],
    padding: bytes = b"",
    kind: str = "data",
) -> Pair:
    """Section 3.4.3: a Data Set of a template the collector has."""
    records = [record(keys, row) for row in rows]
    wire = a_set(template_id, b"".join(r.wire for r in records), padding)
    text = {"type": kind, "template_id": template_id, "records": [r.text for r in records]}
    return Pair(wire, text)


def options_data(template_id: int, keys: list[str], rows: list[list[Pair]], padding: bytes = b"") -> Pair:
    """A Data Set of options records."""
    return data(template_id, keys, rows, padding, kind="options_data")


def undecoded(template_id: int, body: bytes) -> Pair:
    """A Data Set of a template the collector lacks: kept as sent."""
    text = {"type": "undecoded", "set_id": template_id, "body": body.hex()}
    return Pair(a_set(template_id, body), text)


def short(value: Pair) -> Pair:
    """Section 7, figure R: a variable-length value after one length
    octet."""
    assert len(value.wire) < 255
    return Pair(u8(len(value.wire)) + value.wire, value.text)


def long(value: Pair) -> Pair:
    """Section 7, figure S: a variable-length value after 255 and two
    length octets."""
    return Pair(u8(255) + u16(len(value.wire)) + value.wire, value.text)


def message(
    sets: list[Pair],
    export_time: int = 1_700_000_000,
    sequence_number: int = 0,
    domain: int = 0,
    src: str = "192.0.2.1",
) -> tuple[Datagram, dict]:
    """Section 3.1. `sequence_number` counts the data records sent before
    this message."""
    body = b"".join(s.wire for s in sets)
    length = 16 + len(body)
    wire = u16(10) + u16(length) + u32(export_time) + u32(sequence_number)
    wire += u32(domain) + body
    text = {
        "protocol": "ipfix",
        "packet": {
            "version": 10,
            "length": length,
            "export_time": export_time,
            "sequence_number": sequence_number,
            "observation_domain_id": domain,
            "sets": [s.text for s in sets],
        },
    }
    return Datagram(wire, src=src, dst_port=4739), text


def raw(payload: bytes) -> tuple[Datagram, None]:
    """A datagram the collector must discard."""
    return Datagram(payload, dst_port=4739), None




V4 = [(8, 4), (12, 4), (2, 4), (1, 4)]


def v4_row(src: str, dst: str, packets: int, octets: int) -> list[Pair]:
    return [IP(src), IP(dst), U(packets, 4), U(octets, 4)]


def ntp(unix_seconds: int, fraction: int, text: str) -> Pair:
    """An NTP timestamp (sections 6.1.9 and 6.1.10): seconds since 1900 and
    a fraction in units of 2^-32 seconds."""
    return Pair(u32(unix_seconds + 2_208_988_800) + u32(fraction), text)


def appendix_a() -> list[Case]:
    a21 = [(8, 4), (12, 4), (15, 4), (2, 4), (1, 4)]
    a22 = [(8, 4), (12, 4), (15, 4, PEN), (2, 4), (1, 4)]
    a41_scope, a41 = [(141, 4)], [(41, 2), (42, 2)]
    a42 = [(41, 2), (42, 4, PEN)]
    a43_scope = [(123, 4, PEN)]
    flows = [
        [IP("192.0.2.12"), IP("192.0.2.254"), IP("192.0.2.1"), U(5009, 4), U(5344385, 4)],
        [IP("192.0.2.27"), IP("192.0.2.23"), IP("192.0.2.2"), U(748, 4), U(388934, 4)],
        [IP("192.0.2.56"), IP("192.0.2.65"), IP("192.0.2.3"), U(5, 4), U(6534, 4)],
    ]
    return [
        case(
            "appendix_a_examples",
            "RFC 7011 appendix A.1 to A.4",
            "The appendix's examples, value for value. The first message is "
            "the one A.1 describes, 152 octets: the Template Set of A.2.1, "
            "the Data Set of A.3, the Options Template Set of A.4.1 (two "
            "padding octets) and a Data Set of two options records. The "
            "second carries the enterprise-specific examples: the Template "
            "Set of A.2.2, the Options Template Sets of A.4.2 and A.4.3, "
            "the Data Set of A.4.4 and data of the other two templates. "
            "The enterprise-specific elements are unknown to the collector "
            "and keep their octets.",
            [
                message(
                    [
                        templates(template(256, a21)),
                        data(256, names(a21), flows),
                        options_templates(options_template(258, a41_scope, a41), padding=b"\0\0"),
                        options_data(258, names(a41_scope + a41), [[U(1, 4), U(345, 2), U(10201, 2)], [U(2, 4), U(690, 2), U(20402, 2)]]),
                    ]
                ),
                message(
                    [
                        templates(template(257, a22)),
                        options_templates(options_template(259, a41_scope, a42), padding=b"\0\0"),
                        options_templates(options_template(260, a43_scope, a41), padding=b"\0\0"),
                        options_data(260, names(a43_scope + a41), [[HEX("00000001"), U(345, 2), U(10201, 2)], [HEX("00000002"), U(690, 2), U(20402, 2)]]),
                        data(257, names(a22), [[IP("192.0.2.12"), IP("192.0.2.254"), HEX("0000002a"), U(5009, 4), U(5344385, 4)]]),
                        options_data(259, names(a41_scope + a42), [[U(1, 4), U(345, 2), HEX("000027d9")]], padding=b"\0\0"),
                    ],
                    sequence_number=5,
                ),
            ],
            tshark={
                "cflow.len": ["152", "164"],
                "cflow.flowset_id": ["2", "256", "3", "258", "2", "3", "3", "260", "257", "259"],
                "cflow.flowset_length": ["28", "64", "24", "20", "32", "28", "28", "20", "24", "16"],
                "cflow.srcaddr": ["192.0.2.12", "192.0.2.27", "192.0.2.56", "192.0.2.12"],
                "cflow.dstaddr": ["192.0.2.254", "192.0.2.23", "192.0.2.65", "192.0.2.254"],
                "cflow.nexthop": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                "cflow.packets": ["5009", "748", "5", "5009"],
                "cflow.octets": ["5344385", "388934", "6534", "5344385"],
            },
        ),
        case(
            "appendix_a_5_variable_length",
            "RFC 7011 appendix A.5",
            "A.5.1: a 5-octet value after a one-octet length. A.5.2: a "
            "1000-octet value after the three-octet length 255, 1000.",
            [
                message(
                    [
                        templates(template(256, [(83, VARIABLE)])),
                        data(256, [name((83,))], [[short(STR("abcde"))], [long(STR("x" * 1000))]]),
                    ]
                )
            ],
            # Wireshark reports the 255 that announces the long form as a
            # short length too.
            tshark={"cflow.string_len_short": ["5", "255"], "cflow.string_len_long": ["1000"]},
        ),
    ]


def section_3() -> list[Case]:
    out = []

    out.append(
        case(
            "s3_1_message_header",
            "RFC 7011 section 3.1",
            "The message header, each field a different value: version, "
            "Length, Export Time, Sequence Number and Observation Domain "
            "ID. Then a message of every field at its highest, and one "
            "that is a header alone (Length 16).",
            [
                message(
                    [templates(template(256, V4)), data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])],
                    export_time=0x0102_0304,
                    sequence_number=0x0506_0708,
                    domain=0x090A_0B0C,
                ),
                message(
                    [templates(template(256, V4)), data(256, names(V4), [v4_row("192.0.2.2", "198.51.100.2", 2, 200)])],
                    export_time=0xFFFF_FFFF,
                    sequence_number=0xFFFF_FFFF,
                    domain=0xFFFF_FFFF,
                ),
                message([], export_time=0, sequence_number=0, domain=0),
            ],
            tshark={
                "cflow.version": ["10", "10", "10"],
                "cflow.len": ["60", "60", "16"],
                "cflow.sequence": [str(0x0506_0708), str(0xFFFF_FFFF), "0"],
                "cflow.od_id": [str(0x090A_0B0C), str(0xFFFF_FFFF), "0"],
            },
        )
    )

    # An enterprise-specific element shares nothing with the IANA element
    # of the same number: (PEN, 8) is not sourceIPv4Address.
    specs = [(8, 4), (8, 4, PEN), (1, 2, 0xFFFF_FFFF), (32767, 2, 1), (32767, 1), (12, 4)]
    out.append(
        case(
            "s3_2_field_specifier",
            "RFC 7011 section 3.2",
            "Field specifiers with and without the enterprise bit. With "
            "it, four more octets carry the enterprise number and the "
            "element belongs to that enterprise: element 8 of enterprise "
            "32473 is not IANA's sourceIPv4Address. Enterprise numbers 1 "
            "and 4294967295, and the highest element ID, 32767, in both "
            "spaces. The elements the collector has no definition of keep "
            "their octets, and the fields after them are read at the right "
            "offset.",
            [
                message(
                    [
                        templates(template(256, specs)),
                        data(
                            256,
                            names(specs),
                            [
                                [IP("192.0.2.1"), HEX("c6336401"), HEX("beef"), HEX("0102"), HEX("7f"), IP("198.51.100.1")],
                                [IP("192.0.2.2"), HEX("00000000"), HEX("0000"), HEX("ffff"), HEX("00"), IP("198.51.100.2")],
                            ],
                            padding=b"\0\0",
                        ),
                    ]
                )
            ],
            tshark={
                "cflow.srcaddr": ["192.0.2.1", "192.0.2.2"],
                "cflow.dstaddr": ["198.51.100.1", "198.51.100.2"],
            },
        )
    )

    five = [(8, 4), (4, 1)]
    seven = [(12, 4), (7, 2), (5, 1)]
    nine = [(1, 8), (4, 1)]
    out.append(
        case(
            "s3_3_1_set_padding",
            "RFC 7011 sections 3.3.1 and 9",
            "Sets padded to 4-octet and 8-octet boundaries; the padding is "
            "shorter than any record of the Set and is not read as one. "
            "Data records of 5 octets with 3, 2 and 1 padding octets, of 7 "
            "with 1, of 9 with 7 (an 8-octet boundary), and an Options "
            "Template Set with 2. One Data Set is padded with non-zero "
            "octets, which does not make the message malformed (section "
            "9.1).",
            [
                message(
                    [
                        templates(template(256, five), template(257, seven), template(258, nine)),
                        options_templates(options_template(259, [(141, 4)], [(41, 2), (42, 2)]), padding=b"\0\0"),
                    ]
                ),
                message(
                    [
                        data(256, names(five), [[IP("192.0.2.1"), U(6, 1)]], padding=b"\0\0\0"),
                        data(256, names(five), [[IP("192.0.2.2"), U(17, 1)], [IP("192.0.2.3"), U(1, 1)]], padding=b"\0\0"),
                        data(256, names(five), [[IP(f"192.0.2.{i}"), U(i, 1)] for i in (4, 5, 6)], padding=b"\0"),
                        data(257, names(seven), [[IP("198.51.100.1"), U(443, 2), U(184, 1)]], padding=b"\0"),
                        data(258, names(nine), [[U(2**40, 8), U(47, 1)]], padding=b"\0" * 7),
                        options_data(259, ["lineCardId", name((41,)), name((42,))], [[U(1, 4), U(345, 2), U(10201, 2)]]),
                    ],
                    sequence_number=0,
                ),
                message(
                    [data(256, names(five), [[IP("192.0.2.7"), U(7, 1)], [IP("192.0.2.8"), U(8, 1)]], padding=b"\xaa\xbb")],
                    sequence_number=9,
                ),
            ],
            tshark={
                "cflow.flowset_length": ["44", "24", "12", "16", "20", "12", "20", "12", "16"],
                "cflow.srcaddr": [f"192.0.2.{i}" for i in range(1, 9)],
                "cflow.dstaddr": ["198.51.100.1"],
            },
        )
    )

    reserved = [Pair(a_set(i, bytes([i]) * 8), {"type": "unknown", "set_id": i}) for i in (0, 1, 4, 255)]
    out.append(
        case(
            "s3_3_2_set_ids",
            "RFC 7011 section 3.3.2",
            "Set IDs: 2 is a Template Set, 3 an Options Template Set, 256 "
            "and above a Data Set. 0 and 1 are not used and 4 to 255 are "
            "reserved: a collector steps over such a Set by its Length and "
            "reads the Sets around it.",
            [
                message(
                    [
                        reserved[0],
                        templates(template(256, V4)),
                        reserved[1],
                        reserved[2],
                        data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)]),
                        reserved[3],
                        options_templates(options_template(257, [(141, 4)], [(41, 4)])),
                        options_data(257, ["lineCardId", name((41,))], [[U(3, 4), U(33, 4)]]),
                    ]
                )
            ],
            clean=False,
        )
    )

    one = [(4, 1)]
    twice = [(7, 2), (8, 4), (7, 2), (8, 4), (8, 4)]
    out.append(
        case(
            "s3_4_1_template_record",
            "RFC 7011 sections 3.4.1 and 8",
            "Template records: two in one Template Set, a second Template "
            "Set in the same message, the highest Template ID (65535), a "
            "template of a single one-octet field, and a template holding "
            "an element more than once, whose values are reported in "
            "template order.",
            [
                message(
                    [
                        templates(template(256, V4), template(65535, one)),
                        templates(template(257, twice)),
                        data(65535, names(one), [[U(6, 1)], [U(17, 1)], [U(1, 1)], [U(58, 1)]]),
                        data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)]),
                        data(
                            257,
                            names(twice),
                            [[U(1001, 2), IP("192.0.2.1"), U(1002, 2), IP("192.0.2.2"), IP("192.0.2.3")]],
                        ),
                    ]
                )
            ],
            tshark={
                "cflow.template_id": ["256", "65535", "257"],
                "cflow.protocol": ["6", "17", "1", "58"],
                "cflow.srcport": ["1001", "1002"],
                "cflow.srcaddr": ["192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
            },
        )
    )

    two_scopes = options_template(300, [(141, 4), (10, 4)], [(41, 4), (42, 4)])
    all_scope = options_template(301, [(145, 2), (149, 4)], [])
    enterprise_scope = options_template(302, [(7, 2, PEN)], [(82, 4)])
    out.append(
        case(
            "s3_4_2_options_template_record",
            "RFC 7011 sections 3.4.2.1 and 3.4.2.2",
            "Options template records. Field Count counts the scope fields "
            "too, and the scope fields come first. One template with two "
            "scope fields, one whose fields are all scope fields, one "
            "scoped by an enterprise-specific element; two of them in one "
            "Set.",
            [
                message(
                    [
                        options_templates(two_scopes, all_scope),
                        options_templates(enterprise_scope, padding=b"\0\0"),
                    ]
                ),
                message(
                    [
                        options_data(300, ["lineCardId", "ingressInterface", name((41,)), name((42,))], [[U(1, 4), U(7, 4), U(10, 4), U(20, 4)], [U(2, 4), U(8, 4), U(30, 4), U(40, 4)]]),
                        options_data(301, ["templateId", "observationDomainId"], [[U(256, 2), U(0, 4)]], padding=b"\0\0"),
                        options_data(302, [name((7, 2, PEN)), "interfaceName"], [[HEX("0001"), STR("eth0")]], padding=b"\0\0"),
                    ]
                ),
            ],
            # The fourth is the templateId element of template 301's record.
            tshark={"cflow.template_id": ["300", "301", "302", "256"], "cflow.if_name": ["eth0"]},
        )
    )

    v6 = [(27, 16), (28, 16), (1, 8)]
    out.append(
        case(
            "s3_4_3_data_record",
            "RFC 7011 section 3.4.3",
            "Data records: field values one after another in template "
            "order, with no header of their own. A Data Set of twenty "
            "records, Data Sets of three templates in one message, and two "
            "Data Sets of one template side by side.",
            [
                message([templates(template(256, V4), template(257, v6)), options_templates(options_template(258, [(141, 4)], [(41, 2), (42, 2)]), padding=b"\0\0")]),
                message(
                    [
                        data(256, names(V4), [v4_row(f"192.0.2.{i}", f"198.51.100.{i}", i, i * 1000) for i in range(1, 21)]),
                        data(257, names(v6), [[IP("2001:db8:1::1"), IP("2001:db8:2::2"), U(2**40 + 1, 8)], [IP("2001:db8:1::3"), IP("2001:db8:2::4"), U(2**64 - 1, 8)]]),
                        options_data(258, ["lineCardId", name((41,)), name((42,))], [[U(1, 4), U(345, 2), U(10201, 2)]]),
                        data(256, names(V4), [v4_row("192.0.2.21", "198.51.100.21", 21, 21000)]),
                        data(256, names(V4), [v4_row("192.0.2.22", "198.51.100.22", 22, 22000)]),
                    ]
                ),
            ],
            tshark={
                "cflow.srcaddr": [f"192.0.2.{i}" for i in range(1, 23)],
                "cflow.packets": [str(i) for i in range(1, 23)],
                "cflow.srcaddrv6": ["2001:db8:1::1", "2001:db8:1::3"],
                "cflow.octets": [str(i * 1000) for i in range(1, 21)] + [str(2**40 + 1), str(2**64 - 1), "21000", "22000"],
            },
        )
    )

    return out


def section_4_and_5() -> list[Case]:
    statistics = options_template(256, [(149, 4), (143, 4)], [(41, 8), (42, 8), (40, 8)])
    reliability = options_template(257, [(149, 4), (143, 4)], [(164, 8), (165, 8), (322, 4), (322, 4)])
    exporting = options_template(258, [(130, 4)], [(166, 8), (167, 8), (168, 8), (323, 8), (323, 8)])
    flow_keys = options_template(259, [(145, 2)], [(173, 8)])
    delta = [(8, 4), (158, 4), (159, 4), (150, 4), (151, 4)]
    return [
        case(
            "s4_reporting_options_templates",
            "RFC 7011 sections 4.1 to 4.4",
            "The four options templates the RFC specifies and a record of "
            "each: Metering Process Statistics (4.1), Metering Process "
            "Reliability Statistics (4.2), Exporting Process Reliability "
            "Statistics (4.3) and Flow Keys (4.4). Those of 4.2 and 4.3 "
            "hold the same timestamp element twice, for the first and the "
            "last time; both values are reported, in template order.",
            [
                message([options_templates(statistics, reliability, exporting, flow_keys)]),
                message(
                    [
                        options_data(256, ["observationDomainId", "meteringProcessId", name((41,)), name((42,)), name((40,))], [[U(0, 4), U(7, 4), U(1234, 8), U(567890, 8), U(2**33, 8)]]),
                        options_data(
                            257,
                            ["observationDomainId", "meteringProcessId", name((164,)), name((165,)), name((322,)), name((322,))],
                            [[U(0, 4), U(7, 4), U(12, 8), U(3456, 8), Pair(u32(1_700_000_000), "2023-11-14T22:13:20"), Pair(u32(1_700_000_060), "2023-11-14T22:14:20")]],
                        ),
                        options_data(
                            258,
                            ["exporterIPv4Address", name((166,)), name((167,)), name((168,)), name((323,)), name((323,))],
                            [[IP("192.0.2.1"), U(3, 8), U(40, 8), U(5000, 8), Pair((1_700_000_000_250).to_bytes(8, "big"), "2023-11-14T22:13:20.250"), Pair((1_700_000_001_750).to_bytes(8, "big"), "2023-11-14T22:13:21.750")]],
                        ),
                        # Fields 0, 1 and 3 of template 256 are flow keys.
                        options_data(259, ["templateId", name((173,))], [[U(256, 2), U(0b1011, 8)]], padding=b"\0\0"),
                    ]
                ),
            ],
            # The fifth is the templateId element of the flow keys record.
            tshark={"cflow.template_id": ["256", "257", "258", "259", "256"]},
        ),
        case(
            "s5_timing",
            "RFC 7011 sections 5.1 and 5.2",
            "Export Time is seconds since the UNIX epoch in 32 bits, as "
            "dateTimeSeconds values are. Flow times given as microsecond "
            "offsets from the Export Time (flowStartDeltaMicroseconds and "
            "flowEndDeltaMicroseconds) are unsigned 32-bit integers, up to "
            "about 71 minutes. dateTimeSeconds at the two ends of its "
            "range: the epoch, and one second before it wraps on 7 "
            "February 2106 at 06:28:16.",
            [
                message(
                    [
                        templates(template(256, delta)),
                        data(
                            256,
                            names(delta),
                            [
                                [IP("192.0.2.1"), U(5_000_000, 4), U(1, 4), Pair(u32(1_699_999_995), "2023-11-14T22:13:15"), Pair(u32(1_700_000_000), "2023-11-14T22:13:20")],
                                [IP("192.0.2.2"), U(2**32 - 1, 4), U(0, 4), Pair(u32(0), "1970-01-01T00:00:00"), Pair(u32(2**32 - 1), "2106-02-07T06:28:15")],
                            ],
                        ),
                    ],
                    export_time=1_700_000_000,
                ),
                message([data(256, names(delta), [[IP("192.0.2.3"), U(0, 4), U(0, 4), Pair(u32(951_782_400), "2000-02-29T00:00:00"), Pair(u32(951_868_799), "2000-02-29T23:59:59")]])], export_time=2**32 - 1, sequence_number=2),
            ],
            tshark={"cflow.srcaddr": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]},
        ),
    ]


def section_6() -> list[Case]:
    out = []

    typed = [
        (4, 1), (7, 2), (10, 4), (1, 8), (434, 4), (56, 6), (8, 4), (27, 16),
        (311, 8), (276, 1), (82, 4), (90, 8), (150, 4), (152, 8), (154, 8), (156, 8),
    ]
    rows = [
        [
            U(6, 1), U(443, 2), U(70000, 4), U(2**40 + 5, 8), S(-5, 4),
            MAC("02:00:00:00:00:aa"), IP("192.0.2.1"), IP("2001:db8::1"), F64(0.5),
            Pair(b"\x01", True), STR("eth0"), HEX("0000fde800000064"),
            Pair(u32(1_700_000_000), "2023-11-14T22:13:20"),
            # RFC 7373 section 4.8's example.
            Pair((1_352_140_261_135).to_bytes(8, "big"), "2012-11-05T18:31:01.135"),
            ntp(1_700_000_000, 0x8000_0000, "2023-11-14T22:13:20.500000"),
            ntp(1_700_000_000, 0x4000_0000, "2023-11-14T22:13:20.250000000"),
        ],
        [
            U(255, 1), U(65535, 2), U(2**32 - 1, 4), U(2**64 - 1, 8), S(-(2**31), 4),
            MAC("ff:ff:ff:ff:ff:ff"), IP("255.255.255.255"),
            IP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), F64(-2.5),
            Pair(b"\x02", False), STR("lo00"), HEX("ffffffffffffffff"),
            Pair(u32(0), "1970-01-01T00:00:00"),
            Pair((0).to_bytes(8, "big"), "1970-01-01T00:00:00.000"),
            # The bottom 11 bits of a microsecond fraction are ignored.
            ntp(1_700_000_000, 0x8000_07FF, "2023-11-14T22:13:20.500000"),
            ntp(1_700_000_000, 0, "2023-11-14T22:13:20.000000000"),
        ],
        [
            U(0, 1), U(0, 2), U(0, 4), U(0, 8), S(2**31 - 1, 4),
            MAC("00:00:00:00:00:00"), IP("0.0.0.0"), IP("::"), F64(0.0),
            Pair(b"\x01", True), STR("éab"), HEX("0000000000000000"),
            Pair(u32(951_782_400), "2000-02-29T00:00:00"),
            Pair((951_782_400_999).to_bytes(8, "big"), "2000-02-29T00:00:00.999"),
            ntp(951_782_400, 0xC000_0000, "2000-02-29T00:00:00.750000"),
            ntp(951_782_400, 0x2000_0000, "2000-02-29T00:00:00.125000000"),
        ],
    ]
    out.append(
        case(
            "s6_1_data_type_encodings",
            "RFC 7011 sections 6.1.1 to 6.1.10",
            "A value of every abstract data type the IANA registry uses, at "
            "its full size: unsigned8, 16, 32 and 64, signed32 (two's "
            "complement), macAddress, ipv4Address, ipv6Address, float64 "
            "(IEEE binary64), boolean (1 true, 2 false), string (UTF-8, "
            "one with a two-octet character), octetArray, and the four "
            "dateTime types: seconds and milliseconds since the UNIX "
            "epoch, and NTP timestamps for micro- and nanoseconds. Three "
            "records: ordinary values, the highest values, and the lowest.",
            [message([templates(template(256, typed)), data(256, names(typed), rows)])],
            tshark={
                "cflow.protocol": ["6", "255", "0"],
                "cflow.srcport": ["443", "65535", "0"],
                "cflow.octets": [str(2**40 + 5), str(2**64 - 1), "0"],
                "cflow.srcmac": ["02:00:00:00:00:aa", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"],
                "cflow.srcaddr": ["192.0.2.1", "255.255.255.255", "0.0.0.0"],
                "cflow.srcaddrv6": ["2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::"],
                "cflow.sampling_probability": ["0.5", "-2.5", "0"],
            },
        )
    )

    text = [(10, 4), (82, 4), (83, VARIABLE), (14, 4)]
    out.append(
        case(
            "s6_1_6_ill_formed_utf8",
            "RFC 7011 section 6.1.6",
            "String values that are not well-formed UTF-8 (a lone "
            "continuation octet, an overlong encoding, a truncated "
            "sequence): the collector should detect such values. They are "
            "not read as text but reported as their octets, in "
            "hexadecimal, and the record's other fields are kept; the "
            "record between them, with well-formed strings, is whole.",
            [
                message(
                    [
                        templates(template(256, text)),
                        data(
                            256,
                            names(text),
                            [
                                [U(1, 4), HEX(b"ab\x80c"), short(HEX(b"\xc0\xaf")), U(11, 4)],
                                [U(2, 4), STR("eth1"), short(STR("café → 東京")), U(12, 4)],
                                [U(3, 4), STR("eth2"), short(HEX(b"abc\xe6\x9d")), U(13, 4)],
                            ],
                            padding=b"\0",
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1", "2", "3"], "cflow.outputint": ["11", "12", "13"]},
        )
    )

    reduced = [
        (1, 1), (2, 2), (3, 3), (85, 4), (86, 5), (40, 6), (41, 7), (42, 8),
        (10, 1), (14, 2), (16, 3), (7, 1), (434, 1), (434, 2), (434, 3), (311, 4),
    ]
    out.append(
        case(
            "s6_2_reduced_size_encoding",
            "RFC 7011 section 6.2",
            "Integers and floats sent in fewer octets than their type "
            "implies. unsigned64 elements in 1, 2, 3, 4, 5, 6, 7 and 8 "
            "octets; unsigned32 in 1, 2 and 3; unsigned16 in 1; signed32 "
            "in 1, 2 and 3, where the sign must be preserved; float64 as "
            "float32. Three records: the highest value of each size (the "
            "lowest for the signed ones), the highest positive signed "
            "values, and ordinary values.",
            [
                message(
                    [
                        templates(template(256, reduced)),
                        data(
                            256,
                            names(reduced),
                            [
                                [U(2**8 - 1, 1), U(2**16 - 1, 2), U(2**24 - 1, 3), U(2**32 - 1, 4), U(2**40 - 1, 5), U(2**48 - 1, 6), U(2**56 - 1, 7), U(2**64 - 1, 8), U(255, 1), U(65535, 2), U(2**24 - 1, 3), U(255, 1), S(-128, 1), S(-32768, 2), S(-(2**23), 3), F32(1.5)],
                                [U(1, 1), U(1, 2), U(1, 3), U(1, 4), U(1, 5), U(1, 6), U(1, 7), U(1, 8), U(1, 1), U(1, 2), U(1, 3), U(1, 1), S(127, 1), S(32767, 2), S(2**23 - 1, 3), F32(-0.25)],
                                [U(200, 1), U(0x0102, 2), U(0x010203, 3), U(0x01020304, 4), U(0x0102030405, 5), U(0x010203040506, 6), U(0x01020304050607, 7), U(0x0102030405060708, 8), U(128, 1), U(0x8001, 2), U(0x800001, 3), U(53, 1), S(-1, 1), S(-2, 2), S(-3, 3), F32(1024.0)],
                            ],
                            padding=b"\0",
                        ),
                    ]
                )
            ],
            tshark={
                "cflow.octets": [str(2**8 - 1), "1", "200"],
                "cflow.packets": [str(2**16 - 1), "1", str(0x0102)],
                "cflow.inputint": ["255", "1", "128"],
                "cflow.outputint": ["65535", "1", str(0x8001)],
            },
        )
    )

    return out


def section_7() -> list[Case]:
    specs = [(10, 4), (82, VARIABLE), (83, VARIABLE), (95, VARIABLE), (14, 4)]
    keys = ["ingressInterface", "interfaceName", "interfaceDescription", "applicationId", "egressInterface"]
    return [
        case(
            "s7_variable_length",
            "RFC 7011 section 7",
            "Variable-length elements (field length 65535), each value "
            "carrying its own length: in one octet when below 255, or in "
            "three (255, then two octets) for any length. Three "
            "variable-length fields between two fixed ones, with values "
            "of 0, 1, 254, 255, 256 and 1100 octets, the three-octet form "
            "used for short and for empty values as well, and records of "
            "different sizes following one another in a Set.",
            [
                message(
                    [
                        templates(template(256, specs)),
                        data(
                            256,
                            keys,
                            [
                                [U(1, 4), short(STR("")), short(STR("a")), short(HEX("")), U(11, 4)],
                                [U(2, 4), short(STR("b" * 254)), long(STR("c" * 255)), long(HEX("0d" * 256)), U(12, 4)],
                                [U(3, 4), long(STR("")), long(STR("short, in the long form")), long(HEX("0102030405")), U(13, 4)],
                                [U(4, 4), short(STR("eth0")), short(STR("uplink")), short(HEX("0d000050")), U(14, 4)],
                            ],
                            padding=b"\0",
                        ),
                    ]
                ),
                message(
                    [data(256, keys, [[U(5, 4), long(STR("d" * 1100)), short(STR("after a long one")), short(HEX("ff")), U(15, 4)]])],
                    sequence_number=4,
                ),
            ],
            tshark={
                "cflow.inputint": ["1", "2", "3", "4", "5"],
                "cflow.outputint": ["11", "12", "13", "14", "15"],
            },
        )
    ]


def section_8() -> list[Case]:
    out = []
    wide = [(8, 4), (12, 4), (2, 8), (1, 8)]
    scope, options = [(141, 4)], [(41, 4)]
    option_keys = ["lineCardId", name((41,))]

    out.append(
        case(
            "s8_template_refresh",
            "RFC 7011 sections 8 and 8.4",
            "Over UDP an exporter sends its templates again and again. A "
            "template received again unchanged is not an error and changes "
            "nothing: data before and after it is read alike. The "
            "templates are sent alone, with data, and after data in the "
            "same message.",
            [
                message([templates(template(256, V4)), options_templates(options_template(257, scope, options))]),
                message([data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)]), options_data(257, option_keys, [[U(1, 4), U(10, 4)]])]),
                message([templates(template(256, V4)), options_templates(options_template(257, scope, options))], sequence_number=2),
                message(
                    [
                        data(256, names(V4), [v4_row("192.0.2.2", "198.51.100.2", 2, 200)]),
                        templates(template(256, V4)),
                        data(256, names(V4), [v4_row("192.0.2.3", "198.51.100.3", 3, 300)]),
                        options_data(257, option_keys, [[U(2, 4), U(20, 4)]]),
                    ],
                    sequence_number=2,
                ),
            ],
            tshark={
                "cflow.srcaddr": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                "cflow.octets": ["100", "200", "300"],
            },
        )
    )

    out.append(
        case(
            "s8_1_template_withdrawal",
            "RFC 7011 sections 8.1 and 8.4",
            "Template withdrawals: of template 256, of options template "
            "257, of all templates (Template ID 2 in a Template Set) and "
            "of all options templates (Template ID 3 in an Options "
            "Template Set). Over UDP a collector must ignore them (section "
            "8.4), so the data after each withdrawal is still decoded by "
            "the templates sent before.",
            [
                message([templates(template(256, V4)), options_templates(options_template(257, scope, options))]),
                message([templates(template(256, []))]),
                message([data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])]),
                message([options_templates(options_withdrawal(257))], sequence_number=1),
                message([options_data(257, option_keys, [[U(1, 4), U(10, 4)]])], sequence_number=1),
                message([templates(template(2, [])), options_templates(options_withdrawal(3))], sequence_number=2),
                message(
                    [data(256, names(V4), [v4_row("192.0.2.2", "198.51.100.2", 2, 200)]), options_data(257, option_keys, [[U(2, 4), U(20, 4)]])],
                    sequence_number=2,
                ),
            ],
            # Wireshark expects a scope field count in an options template
            # withdrawal, which has none (figure V), and calls it malformed.
            clean=False,
        )
    )

    out.append(
        case(
            "s8_4_template_id_reuse",
            "RFC 7011 sections 8.1 and 8.4",
            "Over UDP an exporter reuses a Template ID by exporting a new "
            "template for it. Template 256 is sent with a new definition, "
            "and later as an options template: data that follows is read "
            "by the latest definition.",
            [
                message([templates(template(256, V4)), data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])]),
                message([templates(template(256, wide)), data(256, names(wide), [[IP("192.0.2.2"), IP("198.51.100.2"), U(2**32 + 2, 8), U(2**40 + 200, 8)]])], sequence_number=1),
                message([data(256, names(wide), [[IP("192.0.2.3"), IP("198.51.100.3"), U(3, 8), U(300, 8)]])], sequence_number=2),
                message([options_templates(options_template(256, scope, options)), options_data(256, option_keys, [[U(4, 4), U(40, 4)]])], sequence_number=3),
            ],
            # Wireshark keeps the first definition of a template it has
            # seen, so it cannot vouch for what follows the change.
            tshark={"cflow.srcaddr": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]},
        )
    )

    swapped = [(12, 4), (8, 4), (1, 4), (2, 4)]
    ports = [(4, 1), (7, 2), (11, 2)]
    out.append(
        case(
            "s8_template_id_scope",
            "RFC 7011 section 8",
            "Template IDs are unique per Transport Session and Observation "
            "Domain. Template 256 means one thing in domain 1 of exporter "
            "192.0.2.1, another in its domain 2, a third from exporter "
            "192.0.2.2 and a fourth from an exporter reached over IPv6; "
            "data of each is read by its own definition. Domain 3 never "
            "sent a template 256, so its data stays undecoded.",
            [
                message([templates(template(256, V4))], domain=1),
                message([templates(template(256, swapped))], domain=2),
                message([templates(template(256, ports))], domain=1, src="192.0.2.2"),
                message([templates(template(256, [(27, 16), (1, 4)]))], domain=1, src="2001:db8::2"),
                message([data(256, names(V4), [v4_row("192.0.2.10", "198.51.100.10", 1, 2)])], domain=1),
                message([data(256, names(swapped), [[IP("198.51.100.20"), IP("192.0.2.20"), U(3, 4), U(4, 4)]])], domain=2),
                message([data(256, names(ports), [[U(6, 1), U(1024, 2), U(443, 2)], [U(17, 1), U(53, 2), U(5353, 2)]], padding=b"\0\0")], domain=1, src="192.0.2.2"),
                message([data(256, ["sourceIPv6Address", "octetDeltaCount"], [[IP("2001:db8:1::1"), U(600, 4)]])], domain=1, src="2001:db8::2"),
                message([undecoded(256, bytes(range(16)))], domain=3),
            ],
            clean=False,
        )
    )

    row = record(names(V4), v4_row("192.0.2.1", "198.51.100.1", 1, 100)).wire
    out.append(
        case(
            "s8_data_before_template",
            "RFC 7011 sections 8 and 8.4",
            "Over UDP a template may be lost or arrive after its data. A "
            "message is printed as it was read, so the first two keep "
            "their Data Sets undecoded, as sent; once the templates "
            "arrive, data of the same templates is decoded.",
            [
                message([undecoded(256, row)]),
                message([undecoded(257, U(1, 4).wire + U(10, 4).wire)], sequence_number=1),
                message([templates(template(256, V4)), options_templates(options_template(257, scope, options))], sequence_number=2),
                message([data(256, names(V4), [v4_row("192.0.2.2", "198.51.100.2", 2, 200)]), options_data(257, option_keys, [[U(2, 4), U(20, 4)]])], sequence_number=2),
            ],
            clean=False,
        )
    )

    return out


def section_9() -> list[Case]:
    out = []

    unknown = [(8, 4), (30000, 4), (9, 2, PEN), (30001, VARIABLE), (10, VARIABLE, PEN), (12, 4)]
    out.append(
        case(
            "s9_unknown_information_elements",
            "RFC 7011 section 9",
            "Elements the collector does not understand, IANA's and "
            "enterprise-specific, of fixed and of variable length. Their "
            "identifiers are noted (printed by number) with their octets, "
            "and the elements around them are read as usual.",
            [
                message(
                    [
                        templates(template(256, unknown)),
                        data(
                            256,
                            names(unknown),
                            [
                                [IP("192.0.2.1"), HEX("deadbeef"), HEX("cafe"), short(HEX("010203")), long(HEX("aa" * 300)), IP("198.51.100.1")],
                                [IP("192.0.2.2"), HEX("00000000"), HEX("0000"), short(HEX("")), short(HEX("ff")), IP("198.51.100.2")],
                            ],
                            padding=b"\0\0",
                        ),
                    ]
                )
            ],
            tshark={
                "cflow.srcaddr": ["192.0.2.1", "192.0.2.2"],
                "cflow.dstaddr": ["198.51.100.1", "198.51.100.2"],
            },
        )
    )

    good, good_text = message([templates(template(256, V4)), data(256, names(V4), [v4_row("192.0.2.9", "198.51.100.9", 9, 900)])], sequence_number=9)
    payload = good.payload
    out.append(
        case(
            "s9_1_malformed_message_header",
            "RFC 7011 section 9.1",
            "Malformed messages, which a collector must discard: a Length "
            "(15) shorter than a message header, a Length (0), a datagram "
            "cut inside the header, a message cut short of its Length, and "
            "reserved Version values (0, 11 and 0x0a00). The well-formed "
            "message after them is read.",
            [
                raw(payload[:2] + u16(15) + payload[4:]),
                raw(payload[:2] + u16(0) + payload[4:]),
                raw(payload[:15]),
                raw(payload[:-1]),
                raw(u16(0) + payload[2:]),
                raw(u16(11) + payload[2:]),
                raw(u16(0x0A00) + payload[2:]),
                (good, good_text),
            ],
            clean=False,
        )
    )

    def broken(tail: bytes) -> tuple[Datagram, None]:
        """A message of a valid Template Set and Data Set followed by
        `tail`, with a Length that covers it all."""
        body = templates(template(256, V4)).wire
        body += data(256, names(V4), [v4_row("192.0.2.1", "198.51.100.1", 1, 100)]).wire
        body += tail
        return raw(u16(10) + u16(16 + len(body)) + u32(1_700_000_000) + u32(0) + u32(0) + body)

    row = record(names(V4), v4_row("192.0.2.2", "198.51.100.2", 2, 200)).wire
    out.append(
        case(
            "s9_1_malformed_set_length",
            "RFC 7011 section 9.1",
            "Messages with a nonsensical Set Length: a Set longer than its "
            "enclosing message, and Sets whose Length (0 and 3) is shorter "
            "than a Set header. Each message also holds a valid Template "
            "Set and Data Set before the broken Set; the RFC has the "
            "collector discard the message, not just the broken Set, so "
            "nothing of them is reported. The well-formed message after "
            "them is read.",
            [
                broken(u16(256) + u16(4 + len(row) + 1) + row),
                broken(u16(256) + u16(0) + row),
                broken(u16(256) + u16(3) + row),
                (good, good_text),
            ],
            clean=False,
        )
    )

    var = [(10, 4), (82, VARIABLE)]
    var_template = templates(template(257, var))
    whole_record = record(names(var), [U(1, 4), short(STR("eth0"))]).wire

    def overlong(length_octets: bytes) -> tuple[Datagram, None]:
        """A message whose second record's variable-length value claims
        more octets than its Set has left."""
        records = whole_record + U(2, 4).wire + length_octets + b"eth1"
        body = var_template.wire + a_set(257, records)
        return raw(u16(10) + u16(16 + len(body)) + u32(1_700_000_000) + u32(0) + u32(0) + body)

    ok, ok_text = message([var_template, data(257, names(var), [[U(3, 4), short(STR("eth3"))]])], sequence_number=3)
    out.append(
        case(
            "s9_1_malformed_variable_length",
            "RFC 7011 section 9.1",
            "Messages holding a variable-length value longer than its "
            "enclosing Set: a one-octet length of 5 with 4 octets left, "
            "and a three-octet length of 1000. The Template Set and the "
            "first record of each message are valid; the RFC has the "
            "collector discard the message. The well-formed message after "
            "them is read.",
            [overlong(u8(5)), overlong(u8(255) + u16(1000)), (ok, ok_text)],
            clean=False,
            deviation="rustflow keeps both messages, reporting the Data Set as "
            "undecoded octets, where RFC 7011 section 9.1 "
            "has the collector discard a message with such a length.",
        )
    )

    return out


def structured_data() -> list[Case]:
    """RFC 6313. A list is printed with its semantic: a basicList with its
    field specifier and its values, a subTemplateList with its Template
    ID and its records, each a map as a data record is, and a
    subTemplateMultiList with its groups, each the same."""
    out = []
    all_of, ordered = 3, 4

    ports = u8(all_of) + u16(11) + u16(2) + u16(80) + u16(443) + u16(8080)
    enterprise = u8(ordered) + u16(0x8000 | 5) + u16(4) + u32(PEN) + u32(1) + u32(2)
    names_list = u8(ordered) + u16(82) + u16(VARIABLE) + short(STR("eth0")).wire + short(STR("")).wire + long(STR("eth10")).wire
    with_list = [(10, 4), (291, VARIABLE), (14, 4)]
    fixed_list = [(10, 4), (291, len(ports)), (14, 4)]
    out.append(
        case(
            "rfc6313_4_5_1_basic_list",
            "RFC 6313 section 4.5.1",
            "basicList: a semantic octet, a field specifier (with an "
            "enterprise number when its top bit is set) and the values. "
            "Lists of a fixed-length IANA element, of an "
            "enterprise-specific element, of a variable-length element, "
            "and an empty list; in a variable-length field with the one- "
            "and the three-octet length, and in a field of fixed length. "
            "Each list is reported with its semantic, its field specifier "
            "and its values, and the fields before and after it are read.",
            [
                message(
                    [
                        templates(template(256, with_list), template(257, fixed_list)),
                        data(
                            256,
                            names(with_list),
                            [
                                [U(1, 4), short(Pair(ports, listed(all_of, (11, 2), [80, 443, 8080]))), U(11, 4)],
                                [U(2, 4), long(Pair(enterprise, listed(ordered, (5, 4, PEN), ["00000001", "00000002"]))), U(12, 4)],
                                [U(3, 4), short(Pair(names_list, listed(ordered, (82, VARIABLE), ["eth0", "", "eth10"]))), U(13, 4)],
                                [U(4, 4), short(Pair(u8(all_of) + u16(11) + u16(2), listed(all_of, (11, 2), []))), U(14, 4)],
                            ],
                            padding=b"\0\0",
                        ),
                        data(257, names(fixed_list), [[U(5, 4), Pair(ports, listed(all_of, (11, 2), [80, 443, 8080])), U(15, 4)]], padding=b"\0"),
                    ]
                )
            ],
            tshark={
                "cflow.inputint": ["1", "2", "3", "4", "5"],
                "cflow.outputint": ["11", "12", "13", "14", "15"],
            },
        )
    )

    inner = [(8, 4), (7, 2)]
    inner_records = [record(names(inner), [IP("192.0.2.1"), U(1001, 2)]), record(names(inner), [IP("192.0.2.2"), U(1002, 2)])]
    inner_rows = b"".join(r.wire for r in inner_records)
    inner_text = [r.text for r in inner_records]
    sub = u8(all_of) + u16(300) + inner_rows
    with_sub = [(10, 4), (292, VARIABLE), (14, 4)]
    out.append(
        case(
            "rfc6313_4_5_2_sub_template_list",
            "RFC 6313 section 4.5.2",
            "subTemplateList: a semantic octet, a Template ID and records "
            "of that template. A list of two records, an empty list, and a "
            "list of a template the collector does not have, which is "
            "reported with its Template ID and octets. The fields before "
            "and after each list are read.",
            [
                message(
                    [
                        templates(template(300, inner), template(256, with_sub)),
                        data(
                            256,
                            names(with_sub),
                            [
                                [U(1, 4), short(Pair(sub, sub_listed(all_of, 300, inner_text))), U(11, 4)],
                                [U(2, 4), short(Pair(u8(all_of) + u16(300), sub_listed(all_of, 300, []))), U(12, 4)],
                                [U(3, 4), long(Pair(u8(all_of) + u16(999) + inner_rows, sub_listed(all_of, 999, data=inner_rows))), U(13, 4)],
                            ],
                            padding=b"\0\0\0",
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1", "2", "3"], "cflow.outputint": ["11", "12", "13"]},
            clean=False,
        )
    )

    other = [(4, 1)]
    group_a = u16(300) + u16(4 + len(inner_rows)) + inner_rows
    group_b = u16(301) + u16(4 + 3) + bytes([6, 17, 1])
    multi = u8(all_of) + group_a + group_b
    with_multi = [(10, 4), (293, VARIABLE), (14, 4)]
    out.append(
        case(
            "rfc6313_4_5_3_sub_template_multi_list",
            "RFC 6313 section 4.5.3",
            "subTemplateMultiList: a semantic octet, then groups, each a "
            "Template ID, a length covering those four octets and the "
            "records, and records of that template. A list of two groups "
            "of different templates, and a list with no group. The fields "
            "before and after each list are read.",
            [
                message(
                    [
                        templates(template(300, inner), template(301, other), template(256, with_multi)),
                        data(
                            256,
                            names(with_multi),
                            [
                                [U(1, 4), short(Pair(multi, multi_listed(all_of, [group(300, inner_text), group(301, [{"protocolIdentifier": p} for p in (6, 17, 1)])]))), U(11, 4)],
                                [U(2, 4), short(Pair(u8(all_of), multi_listed(all_of, []))), U(12, 4)],
                            ],
                            padding=b"\0\0",
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1", "2"], "cflow.outputint": ["11", "12"]},
        )
    )

    return out


def type_information() -> list[Case]:
    """RFC 5610: an exporter describes its enterprise-specific elements in
    options records, and the collector reads their values by the described
    type."""
    # informationElementDataType values, from IANA's registry of that name.
    UNSIGNED32, SIGNED8, SIGNED16, SIGNED64 = 3, 5, 6, 8
    FLOAT32, STRING, MILLISECONDS, IPV4 = 9, 13, 15, 18
    DEFAULT, QUANTITY, IDENTIFIER = 0, 1, 4

    scope = [(303, 2), (346, 4)]
    options = [(339, 1), (344, 1), (341, VARIABLE)]
    keys = names(scope + options)
    described = [
        (1, UNSIGNED32, IDENTIFIER, "exampleId"),
        (2, SIGNED8, QUANTITY, "exampleSigned8"),
        (3, SIGNED16, QUANTITY, "exampleSigned16"),
        (4, SIGNED64, QUANTITY, "exampleSigned64"),
        (5, FLOAT32, QUANTITY, "exampleFloat32"),
        (6, STRING, DEFAULT, "exampleString"),
        (7, MILLISECONDS, DEFAULT, "exampleTime"),
        (8, IPV4, DEFAULT, "exampleAddress"),
    ]
    type_rows = [[U(i, 2), U(PEN, 4), U(data_type, 1), U(semantics, 1), short(STR(label))] for i, data_type, semantics, label in described]

    specs = [(1, 4, PEN), (2, 1, PEN), (3, 2, PEN), (4, 8, PEN), (5, 4, PEN), (6, VARIABLE, PEN), (7, 8, PEN), (8, 4, PEN), (9, 4, PEN)]
    rows = [
        [U(7, 4), S(-128, 1), S(-2, 2), S(-(2**63), 8), F32(1.5), short(STR("first")), Pair((1_352_140_261_135).to_bytes(8, "big"), "2012-11-05T18:31:01.135"), IP("192.0.2.1"), HEX("00000001")],
        [U(2**32 - 1, 4), S(127, 1), S(32767, 2), S(2**63 - 1, 8), F32(-0.5), short(STR("")), Pair((0).to_bytes(8, "big"), "1970-01-01T00:00:00.000"), IP("198.51.100.1"), HEX("ffffffff")],
    ]
    return [
        case(
            "rfc5610_3_type_information",
            "RFC 5610 sections 3 and 3.9",
            "Type records: options records scoped by informationElementId "
            "and privateEnterpriseNumber that give an element's data type, "
            "semantics and name. Eight elements of enterprise 32473 are "
            "described, among them the types the IANA registry has no "
            "element of (signed8, signed16, signed64, float32); a ninth is "
            "not. Data of a template using all nine follows: the described "
            "elements are read by their described types, the ninth keeps "
            "its octets. The elements are printed under their numbers.",
            [
                message([options_templates(options_template(256, scope, options), padding=b"\0\0")]),
                message([options_data(256, keys, type_rows, padding=b"\0")]),
                message([templates(template(257, specs)), data(257, names(specs), rows, padding=b"\0")], sequence_number=8),
            ],
        )
    ]


def padding_and_malformed_templates() -> list[Case]:
    """RFC 7011 sections 3.3.1 and 9.1: padding after template records,
    and messages whose template records do not hold together."""
    out = []

    domain_options = [(149, 4), (41, 4)]
    out.append(
        case(
            "s3_3_1_template_set_padding",
            "RFC 7011 sections 3.3.1 and 8.4",
            "Padding after the last record of a Template Set (4 zero octets) "
            "and of an Options Template Set (6): padding is shorter than "
            "any record the Set may hold, and over UDP, where withdrawals "
            "are not sent, a template record is at least 8 octets and an "
            "options template record 10. The templates are kept and the "
            "Data Sets after them read. Wireshark reads the padding as "
            "records of Template ID 0, and calls the capture malformed.",
            [
                message(
                    [
                        templates(template(256, [(8, 4)]), padding=b"\0" * 4),
                        options_templates(options_template(258, domain_options[:1], domain_options[1:]), padding=b"\0" * 6),
                        data(256, names([(8, 4)]), [[IP("192.0.2.1")]]),
                        options_data(258, names(domain_options), [[U(0, 4), U(5, 4)]]),
                    ]
                )
            ],
            tshark={"cflow.srcaddr": ["192.0.2.1"]},
            clean=False,
        )
    )

    good, good_text = message([templates(template(300, V4)), data(300, names(V4), [v4_row("192.0.2.9", "198.51.100.9", 9, 900)])])
    row = record(names(V4), v4_row("192.0.2.1", "198.51.100.1", 1, 100)).wire

    def message_of(body: bytes) -> tuple[Datagram, None]:
        return raw(u16(10) + u16(16 + len(body)) + u32(1_700_000_000) + u32(0) + u32(0) + body)

    out.append(
        case(
            "s9_1_templates_of_a_discarded_message",
            "RFC 7011 section 9.1",
            "A message holding Template 300 and then a Set whose Length (2) "
            "is shorter than a Set header is discarded whole, the template "
            "with it: the Data Set of template 300 in the next message is "
            "not decoded. Once a well-formed message brings the template, "
            "its data is.",
            [
                message_of(templates(template(300, V4)).wire + u16(256) + u16(2)),
                message([undecoded(300, row)]),
                (good, good_text),
            ],
            clean=False,
        )
    )

    out.append(
        case(
            "s9_1_template_record_overruns_set",
            "RFC 7011 sections 3.4.1, 3.4.2.2 and 9.1",
            "Template records that do not fit their Set: a Field Count of 5 "
            "with one field specifier, and an options template whose Scope "
            "Field Count (2) is above its Field Count (1). Each message is "
            "malformed and discarded; the well-formed message after them "
            "is read.",
            [
                message_of(a_set(2, u16(300) + u16(5) + u16(8) + u16(4))),
                message_of(a_set(3, u16(301) + u16(1) + u16(2) + u16(149) + u16(4))),
                (good, good_text),
            ],
            clean=False,
        )
    )

    only_variable = [(82, VARIABLE)]
    out.append(
        case(
            "s3_3_1_no_padding_after_variable_length_records",
            "RFC 7011 sections 3.3.1 and 7",
            "A template of a single variable-length field: its shortest "
            "record is one octet, the length octet of an empty value, so "
            "no padding is shorter. The three zero octets after the first "
            "record are three records of an empty interfaceName. Wireshark "
            "does not decode Data of such a template.",
            [
                message(
                    [
                        templates(template(256, only_variable)),
                        data(256, names(only_variable), [[short(STR("eth0"))], [short(STR(""))], [short(STR(""))], [short(STR(""))]]),
                    ]
                )
            ],
            clean=False,
        )
    )

    return out


def encodings() -> list[Case]:
    """RFC 7011 section 6, RFC 7012 and RFC 7373: values at the edges of
    their encodings."""
    out = []

    not_reducible = [(8, 2), (56, 4), (152, 4), (150, 8), (311, 2), (10, 4)]
    out.append(
        case(
            "s6_2_reduced_size_only_for_integers",
            "RFC 7011 section 6.2",
            "Reduced-size encoding applies to integers and to float64 as "
            "float32 only. An ipv4Address in 2 octets, a macAddress in 4, "
            "a dateTimeMilliseconds in 4, a dateTimeSeconds in 8 and a "
            "float64 in 2 are not values of their type: each is reported "
            "as its octets, and the field after them is read. Wireshark "
            "stops at the first of them.",
            [
                message(
                    [
                        templates(template(256, not_reducible)),
                        data(
                            256,
                            names(not_reducible),
                            [[HEX("c000"), HEX("02000000"), HEX("00000001"), HEX("0000000065536f00"), HEX("3ff0"), U(7, 4)]],
                        ),
                    ]
                )
            ],
            clean=False,
        )
    )

    flag = [(276, 1), (10, 4)]
    out.append(
        case(
            "s6_1_5_boolean_values",
            "RFC 7011 section 6.1.5",
            "A boolean is 1 (true) or 2 (false); 0, 3 and 255 are not "
            "booleans, and are reported as their octets.",
            [
                message(
                    [
                        templates(template(256, flag)),
                        data(256, names(flag), [[HEX("00"), U(1, 4)], [HEX("03"), U(2, 4)], [HEX("ff"), U(3, 4)]], padding=b"\0"),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1", "2", "3"]},
        )
    )

    probability = [(311, 8)]
    single = [(311, 4)]
    special = [
        (float("nan"), "NaN"),
        (float("inf"), "+inf"),
        (float("-inf"), "-inf"),
    ]
    out.append(
        case(
            "rfc7373_4_4_float_values",
            "RFC 7373 section 4.4; RFC 7011 sections 6.1.3 and 6.2",
            "Floats JSON has no number for are printed as RFC 7373 writes "
            "them: \"NaN\", \"+inf\" and \"-inf\", as float64 and as "
            "float64 sent in 4 octets. The extremes JSON can hold are "
            "numbers: -0, 1e300 and the smallest subnormal, 5e-324.",
            [
                message(
                    [
                        templates(template(256, probability), template(257, single)),
                        data(
                            256,
                            names(probability),
                            [[Pair(struct.pack(">d", value), text)] for value, text in special]
                            + [[F64(-0.0)], [F64(1e300)], [F64(5e-324)]],
                        ),
                        data(257, names(single), [[Pair(struct.pack(">f", value), text)] for value, text in special]),
                    ]
                )
            ],
        )
    )

    def ntp_seconds(seconds: int, text: str) -> Pair:
        return Pair(u32(seconds) + u32(0), text)

    def rfc3339(unix_seconds: int) -> str:
        moment = datetime.fromtimestamp(unix_seconds, timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".000000"

    ntp_unix = 2_208_988_800
    started = [(154, 8), (10, 4)]
    out.append(
        case(
            "s5_2_ntp_era",
            "RFC 7011 sections 5.2 and 6.1.9",
            "An NTP timestamp's 32-bit seconds wrap in 2036; the era is "
            "implicit. In the packet a value with its top bit clear is "
            "after 2036 and one with it set before (the RFC 4330 pivot): "
            "seconds 5 is 2036-02-07. A flow takes the era nearest the "
            "message's Export Time: seconds 2^31 is 1968-01-20 in the "
            "packet, and 2104-02-26 in a flow exported in 2103.",
            [
                message(
                    [templates(template(256, started)), data(256, names(started), [[ntp_seconds(5, rfc3339(2**32 - ntp_unix + 5)), U(1, 4)]])],
                    export_time=2_100_000_000,
                ),
                message(
                    [data(256, names(started), [[ntp_seconds(2**31, rfc3339(2**31 - ntp_unix)), U(2, 4)]])],
                    export_time=4_200_000_000,
                    sequence_number=1,
                ),
            ],
            tshark={"cflow.inputint": ["1", "2"]},
        )
    )

    reserved = [(0, 4), (8, 4)]
    out.append(
        case(
            "rfc7012_4_reserved_element_zero",
            "RFC 7012 section 4; RFC 7011 section 9",
            "Information Element 0 is reserved: the collector has no "
            "definition of it, so its value is reported as octets under "
            "its number, and the element after it is read.",
            [message([templates(template(256, reserved)), data(256, names(reserved), [[HEX("01020304"), IP("192.0.2.1")]])])],
            tshark={"cflow.srcaddr": ["192.0.2.1"]},
        )
    )

    return out


def more_structured_data() -> list[Case]:
    """RFC 6313: lists within lists, groups of a subTemplateMultiList, and
    lists in options records."""
    out = []
    all_of = 3

    ports = lambda *numbers: u8(all_of) + u16(7) + u16(2) + b"".join(u16(n) for n in numbers)
    of_lists = u8(all_of) + u16(291) + u16(VARIABLE) + short(Pair(ports(80, 443), None)).wire + short(Pair(ports(53), None)).wire
    inner = [(7, 2)]
    inner_list = u8(all_of) + u16(301) + u16(80) + u16(443)
    middle = [(292, VARIABLE)]
    middle_records = short(Pair(inner_list, None)).wire
    outer_list = u8(all_of) + u16(300) + middle_records
    nested = [(10, 4), (291, VARIABLE), (292, VARIABLE)]
    out.append(
        case(
            "rfc6313_5_2_nested_lists",
            "RFC 6313 sections 4.5.1, 4.5.2 and 5.2",
            "Lists inside lists: a basicList of basicLists of ports, and a "
            "subTemplateList whose template holds a subTemplateList. The "
            "outer basicList's values are the inner lists, each with its "
            "own semantic and field; the subTemplateList's records hold "
            "the inner one's.",
            [
                message(
                    [
                        templates(template(301, inner), template(300, middle), template(256, nested)),
                        data(
                            256,
                            names(nested),
                            [
                                [
                                    U(1, 4),
                                    short(Pair(of_lists, listed(all_of, (291, VARIABLE), [listed(all_of, (7, 2), [80, 443]), listed(all_of, (7, 2), [53])]))),
                                    short(Pair(outer_list, sub_listed(all_of, 300, [{"subTemplateList": sub_listed(all_of, 301, [{"sourceTransportPort": 80}, {"sourceTransportPort": 443}])}]))),
                                ]
                            ],
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1"]},
            clean=False,
        )
    )

    rows = u16(80) + u16(443)
    groups = u8(all_of)
    groups += u16(301) + u16(4 + len(rows)) + rows
    groups += u16(302) + u16(4)
    groups += u16(999) + u16(4 + 2) + u16(53)
    groups += u16(301) + u16(4 + 2) + u16(8080)
    with_multi = [(10, 4), (293, VARIABLE)]
    out.append(
        case(
            "rfc6313_4_5_3_groups",
            "RFC 6313 section 4.5.3",
            "subTemplateMultiList groups: two records of template 301, a "
            "group of template 302 with no records (a length of 4, its "
            "header), a group of template 999, which the collector does not "
            "have, and one more record of template 301. Each group is "
            "reported in order with its Template ID: the records, none for "
            "the empty group, and the octets of the unknown one.",
            [
                message(
                    [
                        templates(template(301, inner), template(302, [(4, 1)]), template(256, with_multi)),
                        data(
                            256,
                            names(with_multi),
                            [
                                [
                                    U(1, 4),
                                    short(
                                        Pair(
                                            groups,
                                            multi_listed(
                                                all_of,
                                                [
                                                    group(301, [{"sourceTransportPort": 80}, {"sourceTransportPort": 443}]),
                                                    group(302, []),
                                                    group(999, data=u16(53)),
                                                    group(301, [{"sourceTransportPort": 8080}]),
                                                ],
                                            ),
                                        )
                                    ),
                                ]
                            ],
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["1"]},
            clean=False,
        )
    )

    unassigned = [(10, 4), (291, VARIABLE), (292, VARIABLE), (293, VARIABLE)]
    port_list = lambda semantic: u8(semantic) + u16(7) + u16(2) + u16(80)
    record_list = lambda semantic: u8(semantic) + u16(301) + u16(443)
    group_list = lambda semantic: u8(semantic) + u16(301) + u16(4 + 2) + u16(8080)
    out.append(
        case(
            "rfc6313_4_4_unassigned_semantics",
            "RFC 6313 section 4.4",
            "List semantics IANA has not assigned (5 and 254) are reported "
            "as sent, next to the undefined semantic (255), in each kind of "
            "list.",
            [
                message(
                    [
                        templates(template(301, inner), template(256, unassigned)),
                        data(
                            256,
                            names(unassigned),
                            [
                                [
                                    U(semantic, 4),
                                    short(Pair(port_list(semantic), listed(semantic, (7, 2), [80]))),
                                    short(Pair(record_list(semantic), sub_listed(semantic, 301, [{"sourceTransportPort": 443}]))),
                                    short(Pair(group_list(semantic), multi_listed(semantic, [group(301, [{"sourceTransportPort": 8080}])]))),
                                ]
                                for semantic in (5, 0xFE, 0xFF)
                            ],
                            padding=b"\0",
                        ),
                    ]
                )
            ],
            tshark={"cflow.inputint": ["5", "254", "255"]},
        )
    )

    interfaces = u8(all_of) + u16(10) + u16(4) + u32(1) + u32(2)
    empty_elements = u8(all_of) + u16(10) + u16(0)
    scoped = [(291, VARIABLE)]
    counted = [(41, 4)]
    out.append(
        case(
            "rfc6313_5_3_lists_in_options_records",
            "RFC 6313 sections 4.5.1 and 5.3",
            "A basicList as the scope of an options template: the options "
            "records are reported with the list as their scope value. The "
            "second record's list has an element length of 0, which holds "
            "no values.",
            [
                message(
                    [
                        options_templates(options_template(256, scoped, counted)),
                        options_data(
                            256,
                            names(scoped + counted),
                            [[short(Pair(interfaces, listed(all_of, (10, 4), [1, 2]))), U(5, 4)], [short(Pair(empty_elements, listed(all_of, (10, 0), []))), U(6, 4)]],
                        ),
                    ]
                )
            ],
            clean=False,
        )
    )

    return out


def more_type_information() -> list[Case]:
    """RFC 5610: what a type record may and may not change."""
    UNSIGNED32, STRING, IPV4 = 3, 13, 18
    DEFAULT, QUANTITY, IDENTIFIER = 0, 1, 4
    scope = [(303, 2), (346, 4)]
    options = [(339, 1), (344, 1)]
    keys = names(scope + options)
    type_template = options_templates(options_template(256, scope, options), padding=b"\0\0")

    def described(element_id: int, enterprise: int, data_type: int, semantics: int) -> list[Pair]:
        return [U(element_id, 2), U(enterprise, 4), U(data_type, 1), U(semantics, 1)]

    out = []
    enterprise_bit = [(1, 4, PEN)]
    out.append(
        case(
            "rfc5610_3_8_enterprise_bit",
            "RFC 5610 section 3.8",
            "A type record whose informationElementId has the Enterprise "
            "bit set (0x8001): the bit is ignored, the enterprise being in "
            "privateEnterpriseNumber, so element 1 of enterprise 32473 is "
            "described and its value read as an unsigned32.",
            [
                message([type_template, options_data(256, keys, [described(0x8001, PEN, UNSIGNED32, IDENTIFIER)])]),
                message([templates(template(257, enterprise_bit)), data(257, names(enterprise_bit), [[U(7, 4)]])]),
            ],
        )
    )

    used = [(8, 4), (2, 4, PEN), (3, 4, PEN), (600, 4)]
    out.append(
        case(
            "rfc5610_3_9_what_a_type_record_may_change",
            "RFC 5610 sections 3.9 and 3.10",
            "Type records that must not take effect: one giving IANA's "
            "sourceIPv4Address (8) the type string, which may not override "
            "the collector's definition; two describing element 2 of "
            "enterprise 32473 differently, which conflict; and an "
            "ipv4Address with the semantics quantity, which is not a valid "
            "combination. Their values keep their octets, the IP address "
            "its type. A record for element 600, which IANA has not "
            "assigned, does take effect.",
            [
                message(
                    [
                        type_template,
                        options_data(
                            256,
                            keys,
                            [
                                described(8, 0, STRING, DEFAULT),
                                described(2, PEN, UNSIGNED32, QUANTITY),
                                described(2, PEN, STRING, DEFAULT),
                                described(3, PEN, IPV4, QUANTITY),
                                described(600, 0, UNSIGNED32, QUANTITY),
                            ],
                        ),
                    ]
                ),
                message([templates(template(257, used)), data(257, names(used), [[IP("192.0.2.1"), HEX("00000002"), HEX("c0000203"), U(42, 4)]])]),
            ],
        )
    )

    late = [(9, 4, PEN)]
    out.append(
        case(
            "rfc5610_3_9_described_after_its_template",
            "RFC 5610 section 3.9",
            "One message: a template using element 9 of enterprise 32473, "
            "a record of it, the type record describing the element, and "
            "another record. The first record is read before the element "
            "is described and keeps its octets; the second is read as an "
            "unsigned32.",
            [
                message(
                    [
                        type_template,
                        templates(template(257, late)),
                        data(257, names(late), [[HEX("00000001")]]),
                        options_data(256, keys, [described(9, PEN, UNSIGNED32, QUANTITY)]),
                        data(257, names(late), [[U(2, 4)]]),
                    ]
                )
            ],
        )
    )
    return out


def versions() -> list[Case]:
    v5_datagram, v5_text = netflow_v5.packet(
        netflow_v5.header(1, flow_sequence=1),
        [netflow_v5.record(srcaddr="192.0.2.5", dstaddr="198.51.100.5", d_pkts=5, d_octets=500, prot=6)],
    )
    v9_fields = [(12, 4), (8, 4)]
    v9_template = netflow_v9.packet(1, [netflow_v9.templates(netflow_v9.template(256, v9_fields))])
    v9_data = netflow_v9.packet(
        1,
        [netflow_v9.data(256, ["destinationIPv4Address", "sourceIPv4Address"], [[IP("198.51.100.9"), IP("192.0.2.9")]])],
        sequence_number=1,
    )
    return [
        case(
            "s3_1_version_number",
            "RFC 7011 section 3.1; RFC 3954 section 5.1",
            "One exporter sends NetFlow v5, NetFlow v9 and IPFIX to one "
            "port; the Version field tells them apart. Template 256 of "
            "observation domain 0 is defined once in NetFlow v9 and once, "
            "differently, in IPFIX: the two protocols keep separate "
            "templates, and data of each is read by its own.",
            [
                v9_template,
                message([templates(template(256, V4))]),
                (v5_datagram, v5_text),
                v9_data,
                message([data(256, names(V4), [v4_row("192.0.2.10", "198.51.100.10", 10, 1000)])]),
            ],
        )
    ]


def cases() -> list[Case]:
    return [
        *appendix_a(),
        *section_3(),
        *versions(),
        *section_4_and_5(),
        *section_6(),
        *section_7(),
        *section_8(),
        *section_9(),
        *structured_data(),
        *type_information(),
        *padding_and_malformed_templates(),
        *encodings(),
        *more_structured_data(),
        *more_type_information(),
    ]
