"""sFlow version 5 cases.

sFlow has no RFC. The reference is "sFlow Version 5" (sflow.org, July
2004), whose section 5, "sFlow Datagram Format", defines every structure
in XDR (RFC 4506): all integers are 32 or 64 bits, big-endian, and
variable-length data is padded with zeros to a multiple of four bytes.
Dropped-packet notifications are from "sFlow Dropped Packet Notification
Structures" (sflow.org, October 2020).
"""

import ipaddress

from wire import Case, Datagram, Pair, frame, ip, mac, u32, u64

SPEC = "sFlow Version 5 section 5"
DROPS = "sFlow Dropped Packet Notification Structures section 2"

HEADER_PROTOCOLS = {
    1: "EthernetIso88023",
    2: "Iso88024TokenBus",
    3: "Iso88025TokenRing",
    4: "Fddi",
    5: "FrameRelay",
    6: "X25",
    7: "Ppp",
    8: "Smds",
    9: "Aal5",
    10: "Aal5Ip",
    11: "Ipv4",
    12: "Ipv6",
    13: "Mpls",
    14: "Pos",
}


def opaque(data: bytes) -> bytes:
    """XDR variable-length opaque data (RFC 4506 section 4.10)."""
    return u32(len(data)) + data + b"\0" * (-len(data) % 4)


def address(value: str | None) -> Pair:
    """`union address`: a type, then 0, 4 or 16 bytes."""
    if value is None:
        return Pair(u32(0), None)
    parsed = ipaddress.ip_address(value)
    return Pair(u32(1 if parsed.version == 4 else 2) + parsed.packed, str(parsed))


def data_format(enterprise: int, number: int) -> bytes:
    """`data_format`: 20 bits of enterprise, 12 of format number."""
    return u32(enterprise << 12 | number)


def structure(variant: str, number: int, fields: list[tuple[str, bytes, object]]) -> Pair:
    """A standard record: its format, its length, its fields; printed as
    the variant holding the fields by name."""
    body = b"".join(wire for _, wire, _ in fields)
    text = {variant: {key: value for key, _, value in fields}}
    return Pair(data_format(0, number) + opaque(body), text)


def unknown(enterprise: int, number: int, body: bytes) -> Pair:
    """A sample or record of a format the collector does not know, kept as
    sent."""
    text = {"Unknown": {"format": {"enterprise": enterprise, "format": number}, "data": list(body)}}
    return Pair(data_format(enterprise, number) + opaque(body), text)


def n32(key: str, value: int) -> tuple[str, bytes, object]:
    return key, u32(value), value


def n64(key: str, value: int) -> tuple[str, bytes, object]:
    return key, u64(value), value


def signed32(key: str, value: int) -> tuple[str, bytes, object]:
    return key, value.to_bytes(4, "big", signed=True), value


def addr(key: str, value: str | None) -> tuple[str, bytes, object]:
    pair = address(value)
    return key, pair.wire, pair.text


def fixed_ip(key: str, value: str) -> tuple[str, bytes, object]:
    """`ip_v4` or `ip_v6`: fixed-length opaque, without a type."""
    return key, ip(value), str(ipaddress.ip_address(value))


def mac_field(key: str, value: str) -> tuple[str, bytes, object]:
    """`mac`: six bytes of fixed-length opaque, padded to eight."""
    return key, mac(value) + b"\0\0", value


def text_field(key: str, value: str) -> tuple[str, bytes, object]:
    return key, opaque(value.encode()), value


def bytes_field(key: str, value: bytes) -> tuple[str, bytes, object]:
    return key, opaque(value), list(value)


def array(items: list[bytes]) -> bytes:
    """An XDR variable-length array: a count, then the elements."""
    return u32(len(items)) + b"".join(items)


# Flow records.


def sampled_header(protocol: int, frame_length: int, stripped: int, header: bytes) -> Pair:
    name = HEADER_PROTOCOLS.get(protocol, {"Unassigned": protocol})
    return structure(
        "SampledHeader",
        1,
        [
            ("protocol", u32(protocol), name),
            n32("frame_length", frame_length),
            n32("stripped", stripped),
            bytes_field("header", header),
        ],
    )


def sampled_ethernet(length: int, src: str, dst: str, ether_type: int) -> Pair:
    return structure(
        "SampledEthernet",
        2,
        [n32("length", length), mac_field("src_mac", src), mac_field("dst_mac", dst), n32("type", ether_type)],
    )


def sampled_ip(variant, number, last, length, protocol, src, dst, src_port, dst_port, tcp_flags, value) -> Pair:
    return structure(
        variant,
        number,
        [
            n32("length", length),
            n32("protocol", protocol),
            fixed_ip("src_ip", src),
            fixed_ip("dst_ip", dst),
            n32("src_port", src_port),
            n32("dst_port", dst_port),
            n32("tcp_flags", tcp_flags),
            n32(last, value),
        ],
    )


def sampled_ipv4(*fields) -> Pair:
    return sampled_ip("SampledIpv4", 3, "tos", *fields)


def sampled_ipv6(*fields) -> Pair:
    return sampled_ip("SampledIpv6", 4, "priority", *fields)


def extended_switch(src_vlan: int, src_priority: int, dst_vlan: int, dst_priority: int) -> Pair:
    return structure(
        "ExtendedSwitch",
        1001,
        [n32("src_vlan", src_vlan), n32("src_priority", src_priority), n32("dst_vlan", dst_vlan), n32("dst_priority", dst_priority)],
    )


def extended_router(nexthop: str | None, src_mask_len: int, dst_mask_len: int) -> Pair:
    return structure(
        "ExtendedRouter",
        1002,
        [addr("nexthop", nexthop), n32("src_mask_len", src_mask_len), n32("dst_mask_len", dst_mask_len)],
    )


def extended_gateway(nexthop, router_as, src_as, src_peer_as, path, communities, localpref) -> Pair:
    """`path` is a list of ("AsSet" or "AsSequence", [AS numbers])."""
    kinds = {"AsSet": 1, "AsSequence": 2}
    segments = [u32(kinds[kind]) + array([u32(n) for n in numbers]) for kind, numbers in path]
    return structure(
        "ExtendedGateway",
        1003,
        [
            addr("nexthop", nexthop),
            n32("as", router_as),
            n32("src_as", src_as),
            n32("src_peer_as", src_peer_as),
            ("dst_as_path", array(segments), [{kind: numbers} for kind, numbers in path]),
            ("communities", array([u32(c) for c in communities]), communities),
            n32("localpref", localpref),
        ],
    )


def extended_user(src_charset: int, src_user: bytes, dst_charset: int, dst_user: bytes) -> Pair:
    return structure(
        "ExtendedUser",
        1004,
        [n32("src_charset", src_charset), bytes_field("src_user", src_user), n32("dst_charset", dst_charset), bytes_field("dst_user", dst_user)],
    )


def extended_url(direction: int, url: str, host: str) -> Pair:
    name = {1: "Src", 2: "Dst"}[direction]
    return structure("ExtendedUrl", 1005, [("direction", u32(direction), name), text_field("url", url), text_field("host", host)])


def extended_egress_queue(queue: int) -> Pair:
    return structure("ExtendedEgressQueue", 1036, [n32("queue", queue)])


def extended_acl(number: int, name: str, direction: int) -> Pair:
    direction_name = {0: "Unknown", 1: "Ingress", 2: "Egress"}[direction]
    return structure("ExtendedAcl", 1037, [n32("number", number), text_field("name", name), ("direction", u32(direction), direction_name)])


def extended_function(symbol: str) -> Pair:
    return structure("ExtendedFunction", 1038, [text_field("symbol", symbol)])


# Counter records. Each list is the structure's fields in order, 64-bit
# ones marked.

IF_COUNTERS = [
    "if_index", "if_type", ("if_speed", 64), "if_direction", "if_status",
    ("if_in_octets", 64), "if_in_ucast_pkts", "if_in_multicast_pkts",
    "if_in_broadcast_pkts", "if_in_discards", "if_in_errors",
    "if_in_unknown_protos", ("if_out_octets", 64), "if_out_ucast_pkts",
    "if_out_multicast_pkts", "if_out_broadcast_pkts", "if_out_discards",
    "if_out_errors", "if_promiscuous_mode",
]
ETHERNET_COUNTERS = [
    "dot3_stats_alignment_errors", "dot3_stats_fcs_errors",
    "dot3_stats_single_collision_frames", "dot3_stats_multiple_collision_frames",
    "dot3_stats_sqe_test_errors", "dot3_stats_deferred_transmissions",
    "dot3_stats_late_collisions", "dot3_stats_excessive_collisions",
    "dot3_stats_internal_mac_transmit_errors", "dot3_stats_carrier_sense_errors",
    "dot3_stats_frame_too_longs", "dot3_stats_internal_mac_receive_errors",
    "dot3_stats_symbol_errors",
]
TOKENRING_COUNTERS = [
    "dot5_stats_line_errors", "dot5_stats_burst_errors", "dot5_stats_ac_errors",
    "dot5_stats_abort_trans_errors", "dot5_stats_internal_errors",
    "dot5_stats_lost_frame_errors", "dot5_stats_receive_congestions",
    "dot5_stats_frame_copied_errors", "dot5_stats_token_errors",
    "dot5_stats_soft_errors", "dot5_stats_hard_errors", "dot5_stats_signal_loss",
    "dot5_stats_transmit_beacons", "dot5_stats_recoverys", "dot5_stats_lobe_wires",
    "dot5_stats_removes", "dot5_stats_singles", "dot5_stats_freq_errors",
]
VG_COUNTERS = [
    "dot12_in_high_priority_frames", ("dot12_in_high_priority_octets", 64),
    "dot12_in_norm_priority_frames", ("dot12_in_norm_priority_octets", 64),
    "dot12_in_ipm_errors", "dot12_in_oversize_frame_errors", "dot12_in_data_errors",
    "dot12_in_null_addressed_frames", "dot12_out_high_priority_frames",
    ("dot12_out_high_priority_octets", 64), "dot12_transition_into_trainings",
    ("dot12_hc_in_high_priority_octets", 64), ("dot12_hc_in_norm_priority_octets", 64),
    ("dot12_hc_out_high_priority_octets", 64),
]
VLAN_COUNTERS = ["vlan_id", ("octets", 64), "ucast_pkts", "multicast_pkts", "broadcast_pkts", "discards"]


def counters(variant: str, number: int, layout: list, values: list[int]) -> Pair:
    assert len(layout) == len(values), variant
    fields = [
        n64(field[0], value) if isinstance(field, tuple) else n32(field, value)
        for field, value in zip(layout, values)
    ]
    return structure(variant, number, fields)


def numbered(layout: list, start: int) -> list[int]:
    """A different value for every field, past 32 bits for the 64-bit
    ones, so that no two fields can be confused."""
    return [
        (1 << 40) + start + i if isinstance(field, tuple) else start + i
        for i, field in enumerate(layout)
    ]


def processor(cpu_5s: int, cpu_1m: int, cpu_5m: int, total_memory: int, free_memory: int) -> Pair:
    return structure(
        "Processor",
        1001,
        [signed32("cpu_5s", cpu_5s), signed32("cpu_1m", cpu_1m), signed32("cpu_5m", cpu_5m), n64("total_memory", total_memory), n64("free_memory", free_memory)],
    )


# Samples.


def source(source_type: int, index: int, expanded: bool) -> tuple[bytes, dict]:
    wire = u32(source_type) + u32(index) if expanded else u32(source_type << 24 | index)
    return wire, {"source_id_type": source_type, "source_id_index": index}


def interface(form: int, value: int, expanded: bool) -> tuple[bytes, dict]:
    wire = u32(form) + u32(value) if expanded else u32(form << 30 | value)
    return wire, {"format": form, "value": value}


def flow_sample(
    sequence_number: int,
    source_id: tuple[int, int],
    sampling_rate: int,
    sample_pool: int,
    drops: int,
    input: tuple[int, int],
    output: tuple[int, int],
    records: list[Pair],
    expanded: bool = False,
) -> Pair:
    source_wire, source_text = source(*source_id, expanded)
    input_wire, input_text = interface(*input, expanded)
    output_wire, output_text = interface(*output, expanded)
    body = u32(sequence_number) + source_wire + u32(sampling_rate) + u32(sample_pool)
    body += u32(drops) + input_wire + output_wire + array([r.wire for r in records])
    text = {
        "sequence_number": sequence_number,
        "source_id": source_text,
        "sampling_rate": sampling_rate,
        "sample_pool": sample_pool,
        "drops": drops,
        "input": input_text,
        "output": output_text,
        "records": [r.text for r in records],
    }
    variant, number = ("ExpandedFlow", 3) if expanded else ("Flow", 1)
    return Pair(data_format(0, number) + opaque(body), {variant: text})


def counters_sample(sequence_number: int, source_id: tuple[int, int], records: list[Pair], expanded: bool = False) -> Pair:
    source_wire, source_text = source(*source_id, expanded)
    body = u32(sequence_number) + source_wire + array([r.wire for r in records])
    text = {"sequence_number": sequence_number, "source_id": source_text, "records": [r.text for r in records]}
    variant, number = ("ExpandedCounters", 4) if expanded else ("Counters", 2)
    return Pair(data_format(0, number) + opaque(body), {variant: text})


def discarded_packet(sequence_number, source_id, drops, input_if_index, output_if_index, reason: tuple[int, object], records) -> Pair:
    """`reason` is the code and the name it is printed as."""
    source_wire, source_text = source(*source_id, True)
    body = u32(sequence_number) + source_wire + u32(drops) + u32(input_if_index)
    body += u32(output_if_index) + u32(reason[0]) + array([r.wire for r in records])
    text = {
        "sequence_number": sequence_number,
        "source_id": source_text,
        "drops": drops,
        "input_if_index": input_if_index,
        "output_if_index": output_if_index,
        "reason": reason[1],
        "records": [r.text for r in records],
    }
    return Pair(data_format(0, 5) + opaque(body), {"Discarded": text})


def datagram(
    samples: list[Pair],
    agent: str | None = "192.0.2.1",
    sub_agent_id: int = 0,
    sequence_number: int = 1,
    uptime: int = 3_600_000,
    src: str = "192.0.2.1",
) -> tuple[Datagram, dict]:
    """`sample_datagram_v5`, after the version."""
    agent_address = address(agent)
    wire = u32(5) + agent_address.wire + u32(sub_agent_id) + u32(sequence_number)
    wire += u32(uptime) + array([s.wire for s in samples])
    text = {
        "protocol": "sflow_v5",
        "packet": {
            "version": 5,
            "agent_address": agent_address.text,
            "sub_agent_id": sub_agent_id,
            "sequence_number": sequence_number,
            "uptime": uptime,
            "samples": [s.text for s in samples],
        },
    }
    return Datagram(wire, src=src, dst_port=6343), text


def raw(payload: bytes) -> tuple[Datagram, None]:
    return Datagram(payload, dst_port=6343), None


def case(name, reference, description, datagrams, **kwargs) -> Case:
    return Case(
        name,
        reference,
        description,
        [d for d, _ in datagrams],
        [text for _, text in datagrams if text is not None],
        **kwargs,
    )


def sampled_frame(payload: bytes, src: str = "192.0.2.50") -> bytes:
    """A whole Ethernet frame to sample: UDP between high ports, which
    Wireshark dissects no further."""
    return frame(Datagram(payload, src=src, src_port=40000, dst_port=50000))


def simple_flow(sequence_number: int, records: list[Pair] | None = None) -> Pair:
    header = sampled_frame(bytes([sequence_number]) * 4)
    records = records or [sampled_header(1, len(header) + 4, 4, header)]
    return flow_sample(sequence_number, (0, 3), 1000, sequence_number * 1000, 0, (0, 3), (0, 4), records)


def cases() -> list[Case]:
    out = []

    out.append(
        case(
            "s5_sample_datagram",
            f"{SPEC}, sample_datagram_v5 and address",
            "The datagram header, each field a different value: agent "
            "address, sub-agent ID, sequence number and uptime. An agent "
            "address of each type: IPv4, IPv6 and unknown, which carries "
            "no bytes. A datagram of no samples, and one with every "
            "integer at its highest.",
            [
                datagram([simple_flow(1)], agent="192.0.2.10", sub_agent_id=0x0102_0304, sequence_number=0x0506_0708, uptime=0x090A_0B0C),
                datagram([simple_flow(2)], agent="2001:db8::10", sub_agent_id=1, sequence_number=2, uptime=3),
                datagram([simple_flow(3)], agent=None, sub_agent_id=4, sequence_number=5, uptime=6),
                datagram([], agent="192.0.2.10", sub_agent_id=7, sequence_number=8, uptime=9),
                datagram([simple_flow(4)], agent="255.255.255.255", sub_agent_id=2**32 - 1, sequence_number=2**32 - 1, uptime=2**32 - 1),
            ],
            tshark={
                "sflow_245.version": ["5"] * 5,
                "sflow_245.agent": ["192.0.2.10", "192.0.2.10", "255.255.255.255"],
                "sflow_245.agent.v6": ["2001:db8::10"],
                "sflow_245.sub_agent_id": [str(0x0102_0304), "1", "4", "7", str(2**32 - 1)],
                "sflow_245.sequence_number": [str(0x0506_0708), "2", "5", "8", str(2**32 - 1)],
                "sflow_245.sysuptime": [str(0x090A_0B0C), "3", "6", "9", str(2**32 - 1)],
                "sflow_245.numsamples": ["1", "1", "1", "0", "1"],
            },
        )
    )

    header = sampled_frame(b"flow")
    out.append(
        case(
            "s5_flow_sample",
            f"{SPEC}, flow_sample (format 1)",
            "A compact flow sample, each field a different value: sequence "
            "number, source ID, sampling rate, sample pool, drops, input "
            "and output. The source ID's top byte is its type and the rest "
            "its index; an interface's top two bits are its format and the "
            "rest its value. A second sample with every field at its "
            "highest, and one of no records.",
            [
                datagram(
                    [
                        flow_sample(0x0102_0304, (0, 0x05_0607), 0x0809_0A0B, 0x0C0D_0E0F, 0x1011_1213, (0, 0x0415_1617), (0, 0x0819_1A1B), [sampled_header(1, len(header) + 4, 4, header)]),
                        flow_sample(2**32 - 1, (255, 2**24 - 1), 2**32 - 1, 2**32 - 1, 2**32 - 1, (3, 2**30 - 1), (3, 2**30 - 1), [extended_switch(1, 2, 3, 4)]),
                        flow_sample(7, (0, 1), 1, 7, 0, (0, 1), (0, 2), []),
                    ]
                )
            ],
            tshark={
                "sflow_245.numsamples": ["3"],
                "sflow.flow_sample.sequence_number": [str(0x0102_0304), str(2**32 - 1), "7"],
                "sflow.flow_sample.sampling_rate": [str(0x0809_0A0B), str(2**32 - 1), "1"],
                "sflow.flow_sample.sample_pool": [str(0x0C0D_0E0F), str(2**32 - 1), "7"],
                "sflow.flow_sample.dropped_packets": [str(0x1011_1213), str(2**32 - 1), "0"],
            },
        )
    )

    def encoded(sequence_number: int, source_id, input, output) -> Pair:
        return flow_sample(sequence_number, source_id, 100, sequence_number * 100, 0, input, output, [extended_switch(10, 0, 20, 0)])

    out.append(
        case(
            "s5_data_source_and_interface",
            f"{SPEC}, sflow_data_source and interface",
            "Source IDs of each type (0 an ifIndex, 1 a VLAN, 2 a physical "
            "entity) and the interface encodings the specification lists: "
            "0x00000002 (ifIndex 2), 0x00000000 (unknown), 0x40000001 "
            "(discarded, reason 1), 0x40000102 (discarded, reason 258), "
            "0x80000007 (sent to 7 interfaces), 0x80000000 (sent to an "
            "unknown number) and 0x3FFFFFFF (no interface: the device "
            "itself).",
            [
                datagram(
                    [
                        encoded(1, (0, 2), (0, 2), (0, 0)),
                        encoded(2, (1, 100), (0, 3), (1, 1)),
                        encoded(3, (2, 5000), (0, 4), (1, 258)),
                        encoded(4, (0, 5), (0, 5), (2, 7)),
                        encoded(5, (0, 6), (0, 6), (2, 0)),
                        encoded(6, (0, 7), (0, 0x3FFF_FFFF), (0, 7)),
                        encoded(7, (0, 8), (0, 8), (0, 0x3FFF_FFFF)),
                    ]
                )
            ],
            tshark={
                "sflow.flow_sample.source_id_class": ["0", "1", "2", "0", "0", "0", "0"],
                "sflow.flow_sample.index": ["2", "100", "5000", "5", "6", "7", "8"],
            },
        )
    )

    out.append(
        case(
            "s5_flow_sample_expanded",
            f"{SPEC}, flow_sample_expanded (format 3)",
            "Expanded flow samples, whose source ID and interfaces each "
            "take two 32-bit integers: a type and an index, a format and a "
            "value. Indexes past what the compact form holds (2^24 and "
            "2^30), and every field at its highest.",
            [
                datagram(
                    [
                        flow_sample(1, (0, 2**24), 2000, 2000, 0, (0, 2**30), (0, 2**30 + 1), [sampled_header(1, len(header) + 4, 4, header)], expanded=True),
                        flow_sample(2, (1, 4094), 2000, 4000, 5, (0, 9), (2, 3), [extended_switch(4094, 7, 4094, 7)], expanded=True),
                        flow_sample(2**32 - 1, (2**32 - 1, 2**32 - 1), 2**32 - 1, 2**32 - 1, 2**32 - 1, (2**32 - 1, 2**32 - 1), (2**32 - 1, 2**32 - 1), [], expanded=True),
                    ]
                )
            ],
            tshark={
                "sflow.flow_sample.sequence_number": ["1", "2", str(2**32 - 1)],
                "sflow.flow_sample.source_id_type": ["0", "1", str(2**32 - 1)],
                "sflow.flow_sample.source_id_index": [str(2**24), "4094", str(2**32 - 1)],
                "sflow.flow_sample.sampling_rate": ["2000", "2000", str(2**32 - 1)],
            },
        )
    )

    if_values = numbered(IF_COUNTERS, 100)
    out.append(
        case(
            "s5_counters_sample",
            f"{SPEC}, counters_sample (format 2) and counters_sample_expanded (format 4)",
            "Counters samples, compact and expanded, with a record of each "
            "standard counter structure: if_counters, ethernet_counters, "
            "tokenring_counters, vg_counters, vlan_counters and processor. "
            "Every counter holds a different value, the 64-bit ones past "
            "32 bits. The processor's CPU percentages are signed: -1 means "
            "unknown.",
            [
                datagram(
                    [
                        counters_sample(
                            0x0102_0304,
                            (0, 0x05_0607),
                            [counters("IfCounters", 1, IF_COUNTERS, if_values), counters("EthernetCounters", 2, ETHERNET_COUNTERS, numbered(ETHERNET_COUNTERS, 200))],
                        ),
                        counters_sample(
                            2,
                            (0, 2**24 + 9),
                            [
                                counters("TokenringCounters", 3, TOKENRING_COUNTERS, numbered(TOKENRING_COUNTERS, 300)),
                                counters("VgCounters", 4, VG_COUNTERS, numbered(VG_COUNTERS, 400)),
                                counters("VlanCounters", 5, VLAN_COUNTERS, numbered(VLAN_COUNTERS, 500)),
                            ],
                            expanded=True,
                        ),
                        counters_sample(3, (2, 1), [processor(1234, 5678, 9999, 2**34, 2**33), processor(-1, -1, -1, 2**64 - 1, 0)]),
                        counters_sample(4, (0, 1), [counters("IfCounters", 1, IF_COUNTERS, [(2**64 - 1) if isinstance(f, tuple) else 2**32 - 1 for f in IF_COUNTERS])]),
                    ]
                )
            ],
            tshark={
                "sflow.counters_sample.sequence_number": [str(0x0102_0304), "2", "3", "4"],
                "sflow_245.ifindex": [str(if_values[0]), str(2**32 - 1)],
                "sflow_245.ifspeed": [str(if_values[2]), str(2**64 - 1)],
                "sflow_245.ifinoct": [str(if_values[5]), str(2**64 - 1)],
                "sflow_245.ifoutoct": [str(if_values[12]), str(2**64 - 1)],
                "sflow_245.ifpromisc": [str(if_values[18]), str(2**32 - 1)],
                "sflow_245.dot3StatsAlignmentErrors": ["200"],
                "sflow_245.dot3StatsSymbolErrors": ["212"],
                "sflow_245.dot5StatsLineErrors": ["300"],
                "sflow_245.dot5StatsFreqErrors": ["317"],
                "sflow_245.dot12InHighPriorityFrames": ["400"],
                "sflow_245.dot12HCOutHighPriorityOctets": [str(2**40 + 413)],
                "sflow_245.vlan_id": ["500"],
                "sflow_245.octets": [str(2**40 + 501)],
                "sflow_245.discards": ["505"],
                "sflow_5.total_memory": [str(2**34), str(2**64 - 1)],
                "sflow_5.free_memory": [str(2**33), "0"],
            },
        )
    )

    frames = [sampled_frame(b"x" * n) for n in (2, 3, 4, 5)]
    ip_packet = frames[0][14:]
    out.append(
        case(
            "s5_sampled_header",
            f"{SPEC}, sampled_header (format 1) and header_protocol",
            "Sampled headers of 44, 45, 46 and 47 bytes, which XDR pads "
            "with 0, 3, 2 and 1 bytes: the header is its length, without "
            "the padding, and the record after it is read. Frame length "
            "and stripped bytes are reported as sent. Header protocols "
            "other than Ethernet: IPv4 (11), and a number the "
            "specification does not assign (99).",
            [
                datagram(
                    [
                        simple_flow(1, [sampled_header(1, 1518, 4, frames[0]), extended_switch(1, 0, 2, 0)]),
                        simple_flow(2, [sampled_header(1, 64, 8, frames[1]), extended_switch(3, 0, 4, 0)]),
                        simple_flow(3, [sampled_header(1, 9018, 4, frames[2]), extended_switch(5, 0, 6, 0)]),
                        simple_flow(4, [sampled_header(1, 2**32 - 1, 2**32 - 1, frames[3]), extended_switch(7, 0, 8, 0)]),
                        simple_flow(5, [sampled_header(11, len(ip_packet), 0, ip_packet)]),
                        simple_flow(6, [sampled_header(99, 100, 0, b"\x01\x02\x03\x04\x05")]),
                        simple_flow(7, [sampled_header(1, 60, 4, b"")]),
                    ]
                )
            ],
            tshark={
                "sflow_245.header_protocol": ["1", "1", "1", "1", "11", "99", "1"],
                "sflow_245.header.frame_length": ["1518", "64", "9018", str(2**32 - 1), str(len(ip_packet)), "100", "60"],
                "sflow_245.header.payload_stripped": ["4", "8", "4", str(2**32 - 1), "0", "0", "4"],
                "sflow_245.header.sampled_header_length": ["44", "45", "46", "47", str(len(ip_packet)), "5", "0"],
                "sflow_245.vlan.in": ["1", "3", "5", "7"],
            },
        )
    )

    out.append(
        case(
            "s5_sampled_ethernet_ipv4_ipv6",
            f"{SPEC}, sampled_ethernet (format 2), sampled_ipv4 (3) and sampled_ipv6 (4)",
            "The parsed packet records: Ethernet frame data, whose MAC "
            "addresses are six bytes padded to eight, and IPv4 and IPv6 "
            "data, whose addresses are fixed-length and carry no type. "
            "Every field holds a different value.",
            [
                datagram(
                    [
                        simple_flow(
                            1,
                            [
                                sampled_ethernet(1518, "02:00:00:00:00:aa", "02:00:00:00:00:bb", 0x0800),
                                sampled_ipv4(1500, 6, "192.0.2.1", "198.51.100.1", 51000, 443, 0x1B, 0xB8),
                            ],
                        ),
                        simple_flow(
                            2,
                            [
                                sampled_ethernet(86, "02:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", 0x86DD),
                                sampled_ipv6(72, 17, "2001:db8:1::1", "2001:db8:2::2", 53, 5353, 0, 0x2E),
                            ],
                        ),
                        simple_flow(3, [sampled_ipv4(2**32 - 1, 255, "255.255.255.255", "0.0.0.0", 65535, 0, 0xFF, 0xFF)]),
                    ]
                )
            ],
            tshark={
                "sflow_245.ethernet.length": ["1518", "86"],
                "sflow_245.ethernet.packet_type": ["0x00000800", "0x000086dd"],
                "sflow_245.ip.length": ["1500", "72", str(2**32 - 1)],
                "sflow_245.ipv4_src": ["192.0.2.1", "255.255.255.255"],
                "sflow_245.ipv4_dst": ["198.51.100.1", "0.0.0.0"],
                "sflow_245.ipv6_src": ["2001:db8:1::1"],
                "sflow_245.ipv6_dst": ["2001:db8:2::2"],
            },
        )
    )

    out.append(
        case(
            "s5_extended_switch_router_gateway",
            f"{SPEC}, extended_switch (format 1001), extended_router (1002) and extended_gateway (1003)",
            "Switch, router and gateway data. A next hop of each address "
            "type: IPv4, IPv6 and unknown. Gateway data with an AS path of "
            "a sequence, a set and another sequence, with communities; one "
            "with an empty path and no communities; and one whose path "
            "holds an empty segment.",
            [
                datagram(
                    [
                        simple_flow(
                            1,
                            [
                                extended_switch(100, 3, 200, 5),
                                extended_router("203.0.113.1", 24, 16),
                                extended_gateway("203.0.113.254", 64496, 64497, 64498, [("AsSequence", [64499, 64500]), ("AsSet", [64501, 64502, 64503]), ("AsSequence", [4_200_000_000])], [0xFDE8_0064, 0xFFFF_FF01], 150),
                            ],
                        ),
                        simple_flow(2, [extended_router("2001:db8:ffff::1", 48, 64), extended_gateway("2001:db8:ffff::fe", 64496, 0, 0, [], [], 100)]),
                        simple_flow(3, [extended_router(None, 0, 0), extended_gateway(None, 1, 2, 3, [("AsSet", []), ("AsSequence", [64510])], [1], 2**32 - 1)]),
                    ]
                )
            ],
            tshark={
                "sflow_245.vlan.in": ["100"],
                "sflow_245.vlan.out": ["200"],
                "sflow_245.pri.in": ["3"],
                "sflow_245.pri.out": ["5"],
                "sflow_245.nexthop": ["203.0.113.1", "203.0.113.254"],
                "sflow_245.nexthop.v6": ["2001:db8:ffff::1", "2001:db8:ffff::fe"],
                "sflow_245.nexthop.src_mask": ["24", "48", "0"],
                "sflow_245.nexthop.dst_mask": ["16", "64", "0"],
                "sflow_245.as": ["64496", "64496", "1"],
                "sflow_245.srcAS": ["64497", "0", "2"],
                "sflow_245.peerAS": ["64498", "0", "3"],
                # Wireshark lists the communities under the same field.
                "sflow_245.dstAS": ["64499", "64500", "64501", "64502", "64503", "4200000000", str(0xFDE8_0064), str(0xFFFF_FF01), "64510", "1"],
                "sflow_245.localpref": ["150", "100", str(2**32 - 1)],
            },
        )
    )

    out.append(
        case(
            "s5_extended_user_url",
            f"{SPEC}, extended_user (format 1004) and extended_url (1005)",
            "User and URL data, whose strings are XDR variable-length: "
            "lengths of 0 to 9 bytes cover every amount of padding, and "
            "the field after each string is read. Users are opaque bytes "
            "with a character set (106 is UTF-8, 3 is ASCII); URLs name "
            "which end is the server.",
            [
                datagram(
                    [
                        simple_flow(1, [extended_user(106, "josé".encode(), 3, b"bob"), extended_url(1, "/", "a.example")]),
                        simple_flow(2, [extended_user(0, b"", 0, b""), extended_url(2, "", "")]),
                        simple_flow(3, [extended_user(3, b"a", 3, b"ab"), extended_url(1, "/ab", "abcd")]),
                        simple_flow(4, [extended_user(3, b"abcdefg", 3, b"abcdefgh"), extended_url(2, "/index.html?q=1", "www.example.com"), extended_switch(1, 2, 3, 4)]),
                    ]
                )
            ],
            tshark={
                "sflow_5.extended_user.source_character_set": ["106", "0", "3", "3"],
                "sflow_5.extended_url.url": ["/", "/ab", "/index.html?q=1"],
                "sflow_245.vlan.in": ["1"],
            },
        )
    )

    vendor_sample = unknown(4413, 1, bytes(range(12)))
    out.append(
        case(
            "s5_unknown_formats",
            f"{SPEC}, data_format, sample_record, flow_record and counter_record",
            "Every sample and record names its format, an enterprise and a "
            "number, and carries its length, so that a receiver can step "
            "over those it does not know. A sample of an enterprise's own "
            "format, flow and counter records of an enterprise's and of "
            "unknown standard formats, and one of no bytes: each is kept "
            "as sent, under its enterprise and format, and what surrounds "
            "it is read. The highest enterprise (2^20 - 1) and format "
            "(4095) numbers.",
            [
                datagram(
                    [
                        vendor_sample,
                        simple_flow(1, [unknown(4413, 7, b"\x01\x02\x03\x04\x05\x06\x07\x08"), extended_switch(1, 0, 2, 0), unknown(0, 4000, b"\xaa\xbb\xcc")]),
                        counters_sample(2, (0, 3), [unknown(2**20 - 1, 4095, b"\xff" * 5), counters("VlanCounters", 5, VLAN_COUNTERS, numbered(VLAN_COUNTERS, 1)), unknown(0, 3000, b"")]),
                        unknown(0, 4000, b"\x00\x00\x00\x01"),
                        simple_flow(3),
                    ]
                )
            ],
            # Wireshark does not step over a sample of an enterprise's
            # format, and calls the datagram malformed.
            tshark={"sflow_245.numsamples": ["5"]},
            clean=False,
        )
    )

    out.append(
        case(
            "s5_several_samples_and_agents",
            f"{SPEC}, sample_datagram_v5",
            "Datagrams of flow and counters samples together, compact and "
            "expanded, from two agents and two sub-agents of one, one "
            "agent reached over IPv6: each datagram is read on its own, "
            "its samples in order.",
            [
                datagram([simple_flow(1), counters_sample(1, (0, 3), [counters("VlanCounters", 5, VLAN_COUNTERS, numbered(VLAN_COUNTERS, 10))]), simple_flow(2)], sub_agent_id=1),
                datagram([simple_flow(1), simple_flow(2), simple_flow(3)], sub_agent_id=2, sequence_number=1),
                datagram(
                    [flow_sample(1, (0, 2**24), 500, 500, 0, (0, 2**24), (0, 2**24 + 1), [extended_switch(1, 0, 1, 0)], expanded=True), counters_sample(1, (0, 2**24), [processor(100, 200, 300, 1000, 500)], expanded=True)],
                    agent="2001:db8::2",
                    src="2001:db8::2",
                ),
            ],
            tshark={"sflow_245.numsamples": ["3", "3", "2"], "sflow_245.sub_agent_id": ["1", "2", "0"]},
        )
    )

    discarded = sampled_frame(b"drop")
    out.append(
        case(
            "drops_discarded_packet",
            f"{DROPS}, discarded_packet (format 5), extended_egress_queue (1036), extended_acl (1037) and extended_function (1038)",
            "Dropped-packet notifications: a sample with an expanded "
            "source ID, drops, input and output ifIndex, a reason and the "
            "records describing the packet. Reasons from the ICMP "
            "unreachable codes (0), from the sFlow codes (257 TTL "
            "exceeded, 258 ACL), and one the specification does not "
            "assign (9999), which is reported by number. The records "
            "added for drops: egress queue, ACL and function.",
            [
                datagram(
                    [
                        discarded_packet(0x0102_0304, (0, 0x0506_0708), 0x090A_0B0C, 0x0D0E_0F10, 0x1112_1314, (258, "Acl"), [sampled_header(1, len(discarded) + 4, 4, discarded), extended_acl(101, "edge-in", 1), extended_egress_queue(3)]),
                        discarded_packet(2, (0, 7), 0, 7, 0, (257, "TtlExceeded"), [sampled_header(1, len(discarded) + 4, 4, discarded), extended_function("ip_forward")]),
                        discarded_packet(3, (0, 8), 0, 0, 8, (0, "NetUnreachable"), [extended_acl(0, "", 0), extended_acl(2, "out", 2)]),
                        discarded_packet(4, (0, 9), 1, 9, 0, (9999, {"Unassigned": 9999}), []),
                    ]
                )
            ],
            clean=False,
        )
    )

    good, good_text = datagram([simple_flow(9)], sequence_number=9)
    payload = good.payload
    two, _ = datagram([simple_flow(1), simple_flow(2)])
    out.append(
        case(
            "truncated_and_other_versions",
            f"{SPEC} (robustness)",
            "Datagrams a collector cannot read are discarded whole: cut "
            "inside the header, cut inside the second sample, announcing "
            "more samples than it holds, of another version (2, 4, 6), and "
            "with an agent address of a type the specification does not "
            "define (3). The whole datagram after them is read.",
            [
                raw(payload[:20]),
                raw(two.payload[:-10]),
                raw(payload[:24] + u32(3) + payload[28:]),
                raw(u32(2) + payload[4:]),
                raw(u32(4) + payload[4:]),
                raw(u32(6) + payload[4:]),
                raw(u32(5) + u32(3) + payload[8:]),
                (good, good_text),
            ],
            clean=False,
        )
    )

    return out
