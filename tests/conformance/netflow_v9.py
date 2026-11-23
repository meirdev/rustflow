"""NetFlow v9 cases, by section of RFC 3954."""

from values import HEX, IP, MAC, STR, U, record
from wire import Case, Datagram, Pair, u16, u32

# Scope field types (section 6.1) and the element each is printed as.
SYSTEM, INTERFACE, LINE_CARD, CACHE, TEMPLATE = 1, 2, 3, 4, 5
SCOPE_TYPES = {
    SYSTEM: "System",
    INTERFACE: "Interface",
    LINE_CARD: "LineCard",
    CACHE: "Cache",
    TEMPLATE: "Template",
}
# The key a scope value is printed under.
SCOPE_NAMES = {
    SYSTEM: "system",
    INTERFACE: "interface",
    LINE_CARD: "lineCard",
    CACHE: "cache",
    TEMPLATE: "template",
}

# Field types (section 8) by the IANA element name they are printed as.
NAMES = {
    1: "octetDeltaCount",
    2: "packetDeltaCount",
    3: "deltaFlowCount",
    4: "protocolIdentifier",
    5: "ipClassOfService",
    6: "tcpControlBits",
    7: "sourceTransportPort",
    8: "sourceIPv4Address",
    9: "sourceIPv4PrefixLength",
    10: "ingressInterface",
    11: "destinationTransportPort",
    12: "destinationIPv4Address",
    13: "destinationIPv4PrefixLength",
    14: "egressInterface",
    15: "ipNextHopIPv4Address",
    16: "bgpSourceAsNumber",
    17: "bgpDestinationAsNumber",
    18: "bgpNextHopIPv4Address",
    21: "flowEndSysUpTime",
    22: "flowStartSysUpTime",
    27: "sourceIPv6Address",
    28: "destinationIPv6Address",
    29: "sourceIPv6PrefixLength",
    30: "destinationIPv6PrefixLength",
    31: "flowLabelIPv6",
    34: "samplingInterval",
    35: "samplingAlgorithm",
    36: "flowActiveTimeout",
    37: "flowIdleTimeout",
    41: "exportedMessageTotalCount",
    42: "exportedFlowRecordTotalCount",
    56: "sourceMacAddress",
    58: "vlanId",
    60: "ipVersion",
    61: "flowDirection",
    62: "ipNextHopIPv6Address",
    70: "mplsTopLabelStackSection",
    80: "destinationMacAddress",
    82: "interfaceName",
    83: "interfaceDescription",
}


def name(field_type: int) -> str:
    # A field type the registry does not name is printed by number.
    return NAMES.get(field_type, str(field_type))


def fields_wire(fields: list[tuple[int, int]]) -> bytes:
    return b"".join(u16(field_type) + u16(length) for field_type, length in fields)


def fields_text(fields: list[tuple[int, int]]) -> list[dict]:
    return [
        {"information_element_id": t, "field_length": length, "enterprise_number": None}
        for t, length in fields
    ]


def scopes_text(scopes: list[tuple[int, int]]) -> list[dict]:
    return [{"field_type": SCOPE_TYPES[t], "length": length} for t, length in scopes]


def flow_set(flow_set_id: int, body: bytes, padding: bytes = b"") -> bytes:
    """FlowSet ID, Length (header and padding included), body, padding."""
    return u16(flow_set_id) + u16(4 + len(body) + len(padding)) + body + padding


def template(template_id: int, fields: list[tuple[int, int]]) -> Pair:
    wire = u16(template_id) + u16(len(fields)) + fields_wire(fields)
    return Pair(wire, {"template_id": template_id, "fields": fields_text(fields)})


def templates(*records: Pair) -> Pair:
    """A Template FlowSet (section 5.2)."""
    wire = flow_set(0, b"".join(r.wire for r in records))
    return Pair(wire, {"type": "templates", "templates": [r.text for r in records]})


def options_template(
    template_id: int, scopes: list[tuple[int, int]], options: list[tuple[int, int]]
) -> Pair:
    """An options template record (section 6.1): the two lengths count the
    bytes of the field definitions, not the fields."""
    wire = u16(template_id) + u16(4 * len(scopes)) + u16(4 * len(options))
    wire += fields_wire(scopes) + fields_wire(options)
    text = {
        "template_id": template_id,
        "scope_fields": scopes_text(scopes),
        "option_fields": fields_text(options),
    }
    return Pair(wire, text)


def options_templates(*records: Pair, padding: bytes = b"") -> Pair:
    """An Options Template FlowSet (section 6.1)."""
    wire = flow_set(1, b"".join(r.wire for r in records), padding)
    text = {"type": "options_templates", "templates": [r.text for r in records]}
    return Pair(wire, text)


def data(
    template_id: int,
    names: list[str],
    rows: list[list[Pair]],
    padding: bytes = b"",
    kind: str = "data",
) -> Pair:
    """A Data FlowSet (sections 5.3 and 6.2) of a template the collector
    has."""
    records = [record(names, row) for row in rows]
    wire = flow_set(template_id, b"".join(r.wire for r in records), padding)
    text = {"type": kind, "template_id": template_id, "records": [r.text for r in records]}
    return Pair(wire, text)


def options_data(template_id: int, names: list[str], rows: list[list[Pair]], padding: bytes = b"") -> Pair:
    """A Data FlowSet of options records (section 6.2)."""
    return data(template_id, names, rows, padding, kind="options_data")


def undecoded(template_id: int, body: bytes) -> Pair:
    """A Data FlowSet of a template the collector lacks: kept as sent."""
    return Pair(
        flow_set(template_id, body),
        {"type": "undecoded", "set_id": template_id, "body": body.hex()},
    )


def packet(
    count: int,
    flow_sets: list[Pair],
    sys_uptime: int = 3_600_000,
    unix_secs: int = 1_700_000_000,
    sequence_number: int = 0,
    source_id: int = 0,
    src: str = "192.0.2.1",
) -> tuple[Datagram, dict]:
    """An export packet (section 5.1). `count` is the number of records of
    every kind in the packet."""
    wire = u16(9) + u16(count) + u32(sys_uptime) + u32(unix_secs)
    wire += u32(sequence_number) + u32(source_id)
    wire += b"".join(flow_set.wire for flow_set in flow_sets)
    text = {
        "protocol": "netflow_v9",
        "packet": {
            "version": 9,
            "count": count,
            "sys_uptime": sys_uptime,
            "unix_secs": unix_secs,
            "sequence_number": sequence_number,
            "source_id": source_id,
            "flow_sets": [flow_set.text for flow_set in flow_sets],
        },
    }
    return Datagram(wire, src=src), text


def case(name, reference, description, packets, **kwargs) -> Case:
    return Case(
        name,
        reference,
        description,
        [datagram for datagram, _ in packets],
        [text for _, text in packets if text is not None],
        **kwargs,
    )


V4 = [(8, 4), (12, 4), (2, 4), (1, 4)]
V4_NAMES = [name(t) for t, _ in V4]


def v4_row(src: str, dst: str, packets: int, octets: int) -> list[Pair]:
    return [IP(src), IP(dst), U(packets, 4), U(octets, 4)]


def cases() -> list[Case]:
    out = []

    # Section 11: the RFC's own example, value for value.
    example = [(8, 4), (12, 4), (15, 4), (2, 4), (1, 4)]
    example_names = [name(t) for t, _ in example]
    line_card = options_template(257, [(LINE_CARD, 2)], [(41, 2), (42, 2)])
    out.append(
        case(
            "s11_examples",
            "RFC 3954 section 11 (11.1 to 11.5)",
            "The export packet of the RFC's examples: a Template FlowSet "
            "(template 256), a Data FlowSet of three flow records, an Options "
            "Template FlowSet (template 257, scoped by line card, with two "
            "padding bytes) and a Data FlowSet of two options records. "
            "Count is 7.",
            [
                packet(
                    7,
                    [
                        templates(template(256, example)),
                        data(
                            256,
                            example_names,
                            [
                                # "198.168.1.12" is the RFC's own spelling.
                                [IP("198.168.1.12"), IP("10.5.12.254"), IP("192.168.1.1"), U(5009, 4), U(5344385, 4)],
                                [IP("192.168.1.27"), IP("10.5.12.23"), IP("192.168.1.1"), U(748, 4), U(388934, 4)],
                                [IP("192.168.1.56"), IP("10.5.12.65"), IP("192.168.1.1"), U(5, 4), U(6534, 4)],
                            ],
                        ),
                        options_templates(line_card, padding=b"\0\0"),
                        options_data(
                            257,
                            ["lineCard", name(41), name(42)],
                            [
                                [U(1, 2), U(345, 2), U(10201, 2)],
                                [U(2, 2), U(690, 2), U(20402, 2)],
                            ],
                        ),
                    ],
                )
            ],
            tshark={
                "cflow.count": ["7"],
                "cflow.flowset_id": ["0", "256", "1", "257"],
                "cflow.flowset_length": ["28", "64", "24", "16"],
                "cflow.srcaddr": ["198.168.1.12", "192.168.1.27", "192.168.1.56"],
                "cflow.dstaddr": ["10.5.12.254", "10.5.12.23", "10.5.12.65"],
                "cflow.nexthop": ["192.168.1.1"] * 3,
                "cflow.packets": ["5009", "748", "5"],
                "cflow.octets": ["5344385", "388934", "6534"],
            },
        )
    )

    # Section 5.1: every header field its own value.
    out.append(
        case(
            "s5_1_header",
            "RFC 3954 section 5.1",
            "The packet header, each field a different value: version, "
            "count, sysUpTime, UNIX secs, sequence number and source ID. "
            "Three packets from two source IDs, with sequence numbers that "
            "are not consecutive: the header is reported as sent.",
            [
                packet(
                    2,
                    [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])],
                    sys_uptime=0x0102_0304,
                    unix_secs=0x0506_0708,
                    sequence_number=0x090A_0B0C,
                    source_id=0x0D0E_0F10,
                ),
                packet(
                    1,
                    [data(256, V4_NAMES, [v4_row("192.0.2.2", "198.51.100.2", 2, 200)])],
                    sys_uptime=0xFFFF_FFFF,
                    unix_secs=0xFFFF_FFFF,
                    sequence_number=0xFFFF_FFFF,
                    source_id=0x0D0E_0F10,
                ),
                packet(1, [templates(template(256, V4))], sys_uptime=0, unix_secs=0, sequence_number=0, source_id=0xFFFF_FFFF),
            ],
            tshark={
                "cflow.count": ["2", "1", "1"],
                "cflow.sequence": [str(0x090A_0B0C), str(0xFFFF_FFFF), "0"],
                "cflow.source_id": [str(0x0D0E_0F10), str(0x0D0E_0F10), str(0xFFFF_FFFF)],
            },
        )
    )

    # Section 5.2: Template FlowSets.
    v6 = [(27, 16), (28, 16), (2, 8)]
    one = [(4, 1)]
    out.append(
        case(
            "s5_2_template_flowset",
            "RFC 3954 section 5.2",
            "Template FlowSets: one holding two template records (256 and "
            "257), a second in the same packet holding a third with the "
            "highest template ID (65535) and a single one-byte field. Data "
            "of each template follows, in the same packet and in the next.",
            [
                packet(
                    5,
                    [
                        templates(template(256, V4), template(257, v6)),
                        templates(template(65535, one)),
                        data(257, [name(t) for t, _ in v6], [[IP("2001:db8:1::1"), IP("2001:db8:2::2"), U(2**40 + 7, 8)]]),
                        data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 3, 300)]),
                    ],
                ),
                packet(
                    4,
                    [data(65535, ["protocolIdentifier"], [[U(6, 1)], [U(17, 1)], [U(1, 1)], [U(58, 1)]])],
                    sequence_number=1,
                ),
            ],
            tshark={
                "cflow.template_id": ["256", "257", "65535"],
                "cflow.srcaddrv6": ["2001:db8:1::1"],
                "cflow.srcaddr": ["192.0.2.1"],
                "cflow.protocol": ["6", "17", "1", "58"],
            },
        )
    )

    # Section 5.3: Data FlowSets and their padding.
    five = [(8, 4), (4, 1)]
    five_names = [name(t) for t, _ in five]
    seven = [(12, 4), (7, 2), (5, 1)]
    seven_names = [name(t) for t, _ in seven]
    out.append(
        case(
            "s5_3_data_flowset_padding",
            "RFC 3954 section 5.3",
            "Data FlowSets padded to a 4-byte boundary. Records of 5 bytes: "
            "one record and 3 padding bytes, two and 2, three and 1, four "
            "and none. Records of 7 bytes: one record and 1 padding byte. "
            "The Length covers the padding, the padding is shorter than a "
            "record, and it must not be read as one. Two Data FlowSets of "
            "one template in a packet are two sets.",
            [
                packet(2, [templates(template(256, five), template(257, seven))]),
                packet(
                    4,
                    [
                        data(256, five_names, [[IP("192.0.2.1"), U(6, 1)]], padding=b"\0\0\0"),
                        data(256, five_names, [[IP("192.0.2.2"), U(17, 1)], [IP("192.0.2.3"), U(1, 1)]], padding=b"\0\0"),
                        data(257, seven_names, [[IP("198.51.100.1"), U(443, 2), U(184, 1)]], padding=b"\0"),
                    ],
                    sequence_number=1,
                ),
                packet(
                    7,
                    [
                        data(256, five_names, [[IP(f"192.0.2.{i}"), U(i, 1)] for i in (4, 5, 6)], padding=b"\0"),
                        data(256, five_names, [[IP(f"192.0.2.{i}"), U(i, 1)] for i in (7, 8, 9, 10)]),
                    ],
                    sequence_number=2,
                ),
            ],
            tshark={
                "cflow.flowset_length": ["32", "12", "16", "12", "20", "24"],
                "cflow.srcaddr": [f"192.0.2.{i}" for i in range(1, 11)],
                "cflow.dstaddr": ["198.51.100.1"],
            },
        )
    )

    # Section 6.1: Options Template FlowSets.
    every_scope = options_template(
        300,
        [(SYSTEM, 4), (INTERFACE, 4), (LINE_CARD, 4), (CACHE, 4), (TEMPLATE, 2)],
        [(34, 4)],
    )
    sampler = options_template(301, [(SYSTEM, 4)], [(34, 4), (35, 1)])
    interface = options_template(302, [(INTERFACE, 4)], [(82, 8), (83, 16)])
    out.append(
        case(
            "s6_1_options_template_flowset",
            "RFC 3954 section 6.1",
            "Options Template FlowSets. Option Scope Length and Option "
            "Length are in bytes, not fields. One template scoped by all "
            "five scope types (System, Interface, Line Card, Cache, "
            "Template), in a FlowSet with two padding bytes; two more "
            "templates in one FlowSet, the second with strings.",
            [
                packet(
                    3,
                    [
                        options_templates(every_scope, padding=b"\0\0"),
                        options_templates(sampler, interface),
                    ],
                ),
                packet(
                    4,
                    [
                        options_data(
                            300,
                            [SCOPE_NAMES[s] for s in (SYSTEM, INTERFACE, LINE_CARD, CACHE, TEMPLATE)] + [name(34)],
                            [[U(0x0A00_0001, 4), U(7, 4), U(2, 4), U(3, 4), U(256, 2), U(1000, 4)]],
                        ),
                        options_data(301, [SCOPE_NAMES[SYSTEM], name(34), name(35)], [[U(1, 4), U(100, 4), U(2, 1)]], padding=b"\0\0\0"),
                        options_data(
                            302,
                            [SCOPE_NAMES[INTERFACE], name(82), name(83)],
                            [
                                [U(1, 4), STR("Gi0/0/1", 8), STR("uplink to core", 16)],
                                [U(2, 4), STR("Te0/1/10", 8), STR("0123456789abcdef", 16)],
                            ],
                        ),
                    ],
                    sequence_number=1,
                ),
            ],
            tshark={
                "cflow.template_id": ["300", "301", "302"],
                "cflow.if_name": ["Gi0/0/1", "Te0/1/10"],
            },
        )
    )

    # Section 6.2: Options Data Records.
    out.append(
        case(
            "s6_2_options_data_record",
            "RFC 3954 section 6.2",
            "Options data records: scope values first, then the option "
            "values, in template order. Scope fields of 1, 2 and 4 bytes; "
            "a FlowSet of three records, and one of a single record with "
            "padding.",
            [
                packet(
                    2,
                    [
                        options_templates(
                            options_template(400, [(LINE_CARD, 1), (INTERFACE, 2)], [(41, 4), (42, 8)]),
                            options_template(401, [(SYSTEM, 4)], [(36, 2), (37, 2), (34, 2)]),
                            padding=b"\0\0",
                        )
                    ],
                ),
                packet(
                    4,
                    [
                        options_data(
                            400,
                            ["lineCard", "interface", name(41), name(42)],
                            [
                                [U(1, 1), U(101, 2), U(11, 4), U(2**33, 8)],
                                [U(2, 1), U(102, 2), U(22, 4), U(2**34, 8)],
                                [U(255, 1), U(65535, 2), U(2**32 - 1, 4), U(2**64 - 1, 8)],
                            ],
                            padding=b"\0\0\0",
                        ),
                        options_data(401, ["system", name(36), name(37), name(34)], [[U(42, 4), U(60, 2), U(15, 2), U(1024, 2)]], padding=b"\0\0"),
                    ],
                    sequence_number=1,
                ),
            ],
        )
    )

    # Section 7: template management.
    wide = [(8, 4), (12, 4), (2, 8), (1, 8)]
    wide_names = [name(t) for t, _ in wide]
    out.append(
        case(
            "s7_template_refresh_and_redefinition",
            "RFC 3954 sections 7 and 9",
            "Template 256 is sent, used, sent again unchanged (a refresh) "
            "and used again; then it is sent with a new definition, which "
            "must override the old one at once (section 9): the data that "
            "follows, in the same packet and the next, is read by the new "
            "definition.",
            [
                packet(2, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])]),
                packet(2, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.2", "198.51.100.2", 2, 200)])], sequence_number=1),
                packet(
                    2,
                    [templates(template(256, wide)), data(256, wide_names, [[IP("192.0.2.3"), IP("198.51.100.3"), U(2**32 + 3, 8), U(2**40 + 300, 8)]])],
                    sequence_number=2,
                ),
                packet(1, [data(256, wide_names, [[IP("192.0.2.4"), IP("198.51.100.4"), U(4, 8), U(400, 8)]])], sequence_number=3),
            ],
            # Wireshark keeps the first definition of a template it has
            # seen, so it cannot vouch for the counters after the change.
            tshark={"cflow.srcaddr": [f"192.0.2.{i}" for i in (1, 2, 3, 4)]},
        )
    )

    swapped = [(12, 4), (8, 4), (1, 4), (2, 4)]
    swapped_names = [name(t) for t, _ in swapped]
    out.append(
        case(
            "s7_template_id_scope",
            "RFC 3954 sections 7 and 9",
            "Template IDs are unique per exporter and per observation "
            "domain (source ID). Template 256 means one thing in source ID "
            "1 of exporter 192.0.2.1, another in its source ID 2, and a "
            "third from exporter 192.0.2.2; data of each is read by its own "
            "definition. Source ID 3 never sent a template 256, so its data "
            "stays undecoded.",
            [
                packet(1, [templates(template(256, V4))], source_id=1),
                packet(1, [templates(template(256, swapped))], source_id=2),
                packet(1, [templates(template(256, [(4, 1), (7, 2), (11, 2), (5, 1), (10, 2)]))], source_id=1, src="192.0.2.2"),
                packet(1, [data(256, V4_NAMES, [v4_row("192.0.2.10", "198.51.100.10", 1, 2)])], source_id=1, sequence_number=1),
                packet(1, [data(256, swapped_names, [[IP("198.51.100.20"), IP("192.0.2.20"), U(3, 4), U(4, 4)]])], source_id=2, sequence_number=1),
                packet(
                    2,
                    [
                        data(
                            256,
                            [name(t) for t in (4, 7, 11, 5, 10)],
                            [[U(6, 1), U(1024, 2), U(443, 2), U(0, 1), U(5, 2)], [U(17, 1), U(53, 2), U(5353, 2), U(184, 1), U(6, 2)]],
                        )
                    ],
                    source_id=1,
                    sequence_number=1,
                    src="192.0.2.2",
                ),
                packet(1, [undecoded(256, bytes(range(16)))], source_id=3),
            ],
            clean=False,
        )
    )

    # Section 8: field types.
    typed = [
        (1, 4), (2, 4), (3, 4), (4, 1), (5, 1), (6, 1), (7, 2), (8, 4), (9, 1),
        (10, 2), (11, 2), (12, 4), (13, 1), (14, 2), (15, 4), (16, 2), (17, 2),
        (18, 4), (21, 4), (22, 4), (56, 6), (58, 2), (60, 1), (61, 1), (70, 3),
        (80, 6),
    ]
    typed_row = [
        U(123456, 4), U(789, 4), U(1, 4), U(6, 1), U(0xB8, 1), U(0x1B, 1), U(51000, 2),
        IP("192.0.2.1"), U(24, 1), U(11, 2), U(443, 2), IP("198.51.100.1"), U(22, 1),
        U(21, 2), IP("203.0.113.1"), U(64496, 2), U(64511, 2), IP("203.0.113.254"),
        U(3_599_000, 4), U(3_590_000, 4), MAC("02:00:00:00:00:aa"), U(100, 2), U(4, 1),
        U(1, 1), HEX("000641"), MAC("02:00:00:00:00:bb"),
    ]
    wide_typed = [(1, 8), (2, 8), (3, 8), (10, 4), (14, 4), (16, 4), (17, 4), (27, 16), (28, 16), (29, 1), (30, 1), (31, 3), (62, 16), (82, 5), (83, 12)]
    wide_row = [
        U(2**40, 8), U(2**33, 8), U(2**32, 8), U(2**24 + 1, 4), U(2**24 + 2, 4),
        U(4_200_000_001, 4), U(4_200_000_002, 4), IP("2001:db8:a::1"), IP("2001:db8:b::2"),
        U(48, 1), U(64, 1), U(0xABCDE, 3), IP("fe80::1"), STR("xe-0", 5), STR("to peer", 12),
    ]
    out.append(
        case(
            "s8_field_types",
            "RFC 3954 section 8",
            "Field types at the lengths section 8 gives them, and at the "
            "other lengths it allows where the length is N: counters "
            "(IN_BYTES, IN_PKTS, FLOWS) of 4 and of 8 bytes, interfaces of 2 "
            "and of 4, AS numbers of 2 and of 4, a 3-byte IPv6 flow label, "
            "a 3-byte MPLS label, MAC addresses, IPv4 and IPv6 addresses, "
            "and names padded with NULs to the field's length.",
            [
                packet(2, [templates(template(256, typed), template(257, wide_typed))]),
                packet(
                    2,
                    [
                        data(256, [name(t) for t, _ in typed], [typed_row], padding=b"\0"),
                        data(257, [name(t) for t, _ in wide_typed], [wide_row], padding=b"\0"),
                    ],
                    sequence_number=1,
                ),
            ],
            tshark={
                "cflow.octets": ["123456", str(2**40)],
                "cflow.srcmac": ["02:00:00:00:00:aa"],
                "cflow.srcaddrv6": ["2001:db8:a::1"],
                "cflow.if_name": ["xe-0"],
                "cflow.if_descr": ["to peer"],
            },
        )
    )

    # 32769 has bit 15 set, which IPFIX reads as "an enterprise number
    # follows". NetFlow v9 has no such bit: the field is four bytes.
    vendor = [(8, 4), (32769, 4), (40001, 2), (1, 4)]
    out.append(
        case(
            "s8_unknown_field_types",
            "RFC 3954 section 8",
            "Field types the collector has no definition for (40001, and "
            "32769, whose top bit means nothing in v9) keep their bytes and "
            "their length, so the fields after them are still read at the "
            "right offset.",
            [
                packet(
                    3,
                    [
                        templates(template(256, vendor)),
                        data(
                            256,
                            [name(t) for t, _ in vendor],
                            [
                                [IP("192.0.2.1"), HEX("deadbeef"), HEX("cafe"), U(1000, 4)],
                                [IP("192.0.2.2"), HEX("00000001"), HEX("0002"), U(2000, 4)],
                            ],
                            padding=b"\0\0",
                        ),
                    ],
                )
            ],
            tshark={"cflow.srcaddr": ["192.0.2.1", "192.0.2.2"], "cflow.octets": ["1000", "2000"]},
        )
    )

    # Section 9: the collector side.
    row = record(V4_NAMES, v4_row("192.0.2.1", "198.51.100.1", 1, 100)).wire
    options_row = U(1, 4).wire + U(100, 4).wire
    out.append(
        case(
            "s9_data_before_template",
            "RFC 3954 section 9",
            "Data and options data arrive before their templates, which the "
            "collector must not assume to be in the same packet. A packet is "
            "printed as it was read, so the first two keep their FlowSets "
            "undecoded, as sent; once the templates arrive, data of the same "
            "templates is decoded.",
            [
                packet(1, [undecoded(256, row)]),
                packet(1, [undecoded(257, options_row)], sequence_number=1),
                packet(2, [templates(template(256, V4)), options_templates(options_template(257, [(SYSTEM, 4)], [(34, 4)]))], sequence_number=2),
                packet(
                    2,
                    [
                        data(256, V4_NAMES, [v4_row("192.0.2.2", "198.51.100.2", 2, 200)]),
                        options_data(257, ["system", name(34)], [[U(1, 4), U(100, 4)]]),
                    ],
                    sequence_number=3,
                ),
            ],
            clean=False,
        )
    )

    out.append(
        case(
            "s9_template_kinds_share_ids",
            "RFC 3954 sections 6.1 and 9",
            "Templates and options templates share one ID space: an options "
            "template sent with the ID of a template overrides it, and the "
            "other way around.",
            [
                packet(2, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])]),
                packet(
                    2,
                    [
                        options_templates(options_template(256, [(INTERFACE, 4)], [(34, 4)])),
                        options_data(256, ["interface", name(34)], [[U(7, 4), U(500, 4)]]),
                    ],
                    sequence_number=1,
                ),
                packet(2, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.2", "198.51.100.2", 2, 200)])], sequence_number=2),
            ],
        )
    )

    # Section 4: FlowSet IDs below 256 other than 0 and 1 are reserved.
    reserved = [Pair(flow_set(i, bytes([i]) * 8), {"type": "unknown", "set_id": i}) for i in (2, 3, 255)]
    out.append(
        case(
            "s4_reserved_flowset_ids",
            "RFC 3954 sections 4 and 5.2",
            "FlowSet IDs 2 to 255 are reserved for FlowSets yet to be "
            "defined. A collector steps over them by their Length and reads "
            "the FlowSets around them.",
            [
                packet(
                    2,
                    [
                        templates(template(256, V4)),
                        reserved[0],
                        reserved[1],
                        data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 1, 100)]),
                        reserved[2],
                    ],
                )
            ],
            clean=False,
        )
    )

    # Robustness: RFC 3954 does not say what to do with these.
    good, good_text = packet(2, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.9", "198.51.100.9", 9, 900)])], sequence_number=9)
    out.append(
        case(
            "truncated_header",
            "RFC 3954 section 5.1 (robustness)",
            "Datagrams cut inside the 20-byte header (19, 10 and 2 bytes) "
            "are discarded; the whole packet after them is read.",
            [(Datagram(good.payload[:n]), None) for n in (19, 10, 2)] + [(good, good_text)],
            clean=False,
        )
    )

    first = packet(1, [templates(template(256, V4))])
    head, _ = packet(3, [templates(template(256, V4)), data(256, V4_NAMES, [v4_row("192.0.2.1", "198.51.100.1", 1, 100)])], sequence_number=1)
    overrun = u16(256) + u16(4 + 32) + row
    short = u16(256) + u16(3) + row
    after, after_text = packet(1, [data(256, V4_NAMES, [v4_row("192.0.2.3", "198.51.100.3", 3, 300)])], sequence_number=2)
    out.append(
        case(
            "truncated_flowset",
            "RFC 3954 sections 5.2 and 5.3 (robustness)",
            "A FlowSet whose Length runs past the end of the datagram, and "
            "one whose Length (3) is shorter than its own header. RFC 3954 "
            "does not say what a collector does; rustflow discards the whole "
            "packet, the FlowSets before the broken one included, and reads "
            "the packets around it.",
            [
                first,
                (Datagram(head.payload + overrun), None),
                (Datagram(head.payload + short), None),
                (after, after_text),
            ],
            clean=False,
        )
    )

    return out
