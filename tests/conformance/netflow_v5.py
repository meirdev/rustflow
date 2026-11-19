"""NetFlow v5 cases.

NetFlow v5 has no RFC. The reference is Cisco's "NetFlow Export Datagram
Format", version 5: a 24-byte header (table "Version 5 Header Format")
followed by `count` 48-byte flow records (table "Version 5 Flow Record
Format").
"""

from wire import Case, Datagram, ip, u8, u16, u32

HEADER = 'Cisco NetFlow Export Datagram Format, "Version 5 Header Format"'
RECORD = 'Cisco NetFlow Export Datagram Format, "Version 5 Flow Record Format"'


def header(
    count: int,
    sys_uptime: int = 3_600_000,
    unix_secs: int = 1_700_000_000,
    unix_nsecs: int = 0,
    flow_sequence: int = 0,
    engine_type: int = 0,
    engine_id: int = 0,
    sampling: int = 0,
    version: int = 5,
) -> tuple[bytes, dict]:
    wire = (
        u16(version)
        + u16(count)
        + u32(sys_uptime)
        + u32(unix_secs)
        + u32(unix_nsecs)
        + u32(flow_sequence)
        + u8(engine_type)
        + u8(engine_id)
        + u16(sampling)
    )
    text = {
        "version": version,
        "count": count,
        "sys_uptime": sys_uptime,
        "unix_secs": unix_secs,
        "unix_nsecs": unix_nsecs,
        "flow_sequence": flow_sequence,
        "engine_type": engine_type,
        "engine_id": engine_id,
        # The first two bits are the mode, the other 14 the interval.
        "sampling_interval": {"mode": sampling >> 14, "interval": sampling & 0x3FFF},
    }
    return wire, text


def record(
    srcaddr: str = "0.0.0.0",
    dstaddr: str = "0.0.0.0",
    nexthop: str = "0.0.0.0",
    input: int = 0,
    output: int = 0,
    d_pkts: int = 0,
    d_octets: int = 0,
    first: int = 0,
    last: int = 0,
    srcport: int = 0,
    dstport: int = 0,
    tcp_flags: int = 0,
    prot: int = 0,
    tos: int = 0,
    src_as: int = 0,
    dst_as: int = 0,
    src_mask: int = 0,
    dst_mask: int = 0,
    pad1: int = 0,
    pad2: int = 0,
) -> tuple[bytes, dict]:
    wire = (
        ip(srcaddr)
        + ip(dstaddr)
        + ip(nexthop)
        + u16(input)
        + u16(output)
        + u32(d_pkts)
        + u32(d_octets)
        + u32(first)
        + u32(last)
        + u16(srcport)
        + u16(dstport)
        + u8(pad1)
        + u8(tcp_flags)
        + u8(prot)
        + u8(tos)
        + u16(src_as)
        + u16(dst_as)
        + u8(src_mask)
        + u8(dst_mask)
        + u16(pad2)
    )
    assert len(wire) == 48
    text = {
        "srcaddr": srcaddr,
        "dstaddr": dstaddr,
        "nexthop": nexthop,
        "input": input,
        "output": output,
        "d_pkts": d_pkts,
        "d_octets": d_octets,
        "first": first,
        "last": last,
        "srcport": srcport,
        "dstport": dstport,
        "tcp_flags": tcp_flags,
        "prot": prot,
        "tos": tos,
        "src_as": src_as,
        "dst_as": dst_as,
        "src_mask": src_mask,
        "dst_mask": dst_mask,
    }
    return wire, text


def packet(head: tuple[bytes, dict], records: list[tuple[bytes, dict]]):
    wire = head[0] + b"".join(r[0] for r in records)
    text = {
        "protocol": "netflow_v5",
        "packet": {**head[1], "flow_records": [r[1] for r in records]},
    }
    return Datagram(wire), text


# Every field a different value, so that two fields swapped or read at the
# wrong width cannot go unnoticed.
DISTINCT = dict(
    srcaddr="192.0.2.17",
    dstaddr="198.51.100.34",
    nexthop="203.0.113.51",
    input=0x0102,
    output=0x0304,
    d_pkts=0x0506_0708,
    d_octets=0x090A_0B0C,
    first=0x0D0E_0F10,
    last=0x1112_1314,
    srcport=0x1516,
    dstport=0x1718,
    tcp_flags=0x19,
    prot=0x1A,
    tos=0x1B,
    src_as=0x1C1D,
    dst_as=0x1E1F,
    src_mask=0x20,
    dst_mask=0x21,
)


def cases() -> list[Case]:
    out = []

    datagram, text = packet(
        header(
            1,
            sys_uptime=0x2223_2425,
            unix_secs=0x2627_2829,
            unix_nsecs=0x2A2B_2C2D,
            flow_sequence=0x2E2F_3031,
            engine_type=0x32,
            engine_id=0x33,
            sampling=0x4064,
        ),
        [record(**DISTINCT)],
    )
    out.append(
        Case(
            "header_and_record_layout",
            f"{HEADER}; {RECORD}",
            "One datagram with one record. Every header and record field "
            "holds a different value, so each must be read from its own "
            "offset and width.",
            [datagram],
            [text],
            tshark={
                "cflow.version": ["5"],
                "cflow.count": ["1"],
                "cflow.sequence": [str(0x2E2F_3031)],
                "cflow.engine_type": [str(0x32)],
                "cflow.engine_id": [str(0x33)],
                "cflow.samplingmode": ["1"],
                "cflow.samplerate": ["100"],
                "cflow.srcaddr": ["192.0.2.17"],
                "cflow.dstaddr": ["198.51.100.34"],
                "cflow.nexthop": ["203.0.113.51"],
                "cflow.inputint": [str(0x0102)],
                "cflow.outputint": [str(0x0304)],
                "cflow.packets": [str(0x0506_0708)],
                "cflow.octets": [str(0x090A_0B0C)],
                "cflow.srcport": [str(0x1516)],
                "cflow.dstport": [str(0x1718)],
                "cflow.protocol": [str(0x1A)],
                "cflow.srcas": [str(0x1C1D)],
                "cflow.dstas": [str(0x1E1F)],
                "cflow.srcmask": [str(0x20)],
                "cflow.dstmask": [str(0x21)],
            },
        )
    )

    records = [
        record(
            srcaddr=f"192.0.2.{i}",
            dstaddr=f"198.51.100.{i}",
            nexthop="203.0.113.1",
            input=1,
            output=2,
            d_pkts=i,
            d_octets=i * 100,
            first=1000 + i,
            last=2000 + i,
            srcport=10000 + i,
            dstport=443,
            tcp_flags=0x18,
            prot=6,
        )
        for i in range(1, 31)
    ]
    datagram, text = packet(header(30, flow_sequence=1000), records)
    out.append(
        Case(
            "count_30_records",
            f'{HEADER}, "count" (1-30)',
            "The largest datagram the format allows: 30 records, 1464 bytes.",
            [datagram],
            [text],
            tshark={
                "cflow.count": ["30"],
                "cflow.srcaddr": [f"192.0.2.{i}" for i in range(1, 31)],
                "cflow.packets": [str(i) for i in range(1, 31)],
            },
        )
    )

    datagram, text = packet(header(0, flow_sequence=7), [])
    out.append(
        Case(
            "count_zero",
            f'{HEADER}, "count"',
            "A header announcing no records is a packet without flows. The format documents a count of 1 to 30, so Wireshark calls this one malformed.",
            [datagram],
            [text],
            clean=False,
        )
    )

    highest = record(
        srcaddr="255.255.255.255",
        dstaddr="255.255.255.255",
        nexthop="255.255.255.255",
        input=0xFFFF,
        output=0xFFFF,
        d_pkts=0xFFFF_FFFF,
        d_octets=0xFFFF_FFFF,
        first=0xFFFF_FFFF,
        last=0xFFFF_FFFF,
        srcport=0xFFFF,
        dstport=0xFFFF,
        tcp_flags=0xFF,
        prot=0xFF,
        tos=0xFF,
        src_as=0xFFFF,
        dst_as=0xFFFF,
        src_mask=0xFF,
        dst_mask=0xFF,
        pad1=0xFF,
        pad2=0xFFFF,
    )
    datagram, text = packet(
        header(
            2,
            sys_uptime=0xFFFF_FFFF,
            unix_secs=0xFFFF_FFFF,
            unix_nsecs=999_999_999,
            flow_sequence=0xFFFF_FFFF,
            engine_type=0xFF,
            engine_id=0xFF,
            sampling=0xFFFF,
        ),
        [highest, record()],
    )
    out.append(
        Case(
            "field_ranges",
            f"{HEADER}; {RECORD}",
            "One record with every field at its highest value and one with "
            "every field zero: all integers are unsigned and none is "
            "truncated. The pad bytes of the first record are non-zero and "
            "must not leak into a field.",
            [datagram],
            [text],
            tshark={
                "cflow.packets": [str(0xFFFF_FFFF), "0"],
                "cflow.octets": [str(0xFFFF_FFFF), "0"],
                "cflow.srcport": ["65535", "0"],
                "cflow.srcas": ["65535", "0"],
            },
        )
    )

    datagrams, texts = [], []
    for sequence, sampling in enumerate([0x0000, 0x4001, 0x8400, 0xC000 | 0x3FFF]):
        datagram, text = packet(
            header(1, flow_sequence=sequence, sampling=sampling),
            [record(srcaddr="192.0.2.1", dstaddr="198.51.100.1", d_pkts=1)],
        )
        datagrams.append(datagram)
        texts.append(text)
    out.append(
        Case(
            "sampling_interval",
            f'{HEADER}, "sampling_interval"',
            "The 16-bit sampling field: the first two bits are the mode, the "
            "remaining 14 the interval. Four datagrams: 0/0, 1/1, 2/1024 and "
            "3/16383.",
            datagrams,
            texts,
            tshark={
                "cflow.samplingmode": ["0", "1", "2", "3"],
                "cflow.samplerate": ["0", "1", "1024", "16383"],
            },
        )
    )

    datagrams, texts = [], []
    for sequence, (src, engine_id) in enumerate(
        [("192.0.2.1", 1), ("192.0.2.2", 1), ("192.0.2.1", 2), ("2001:db8::1", 3)]
    ):
        datagram, text = packet(
            header(2, flow_sequence=sequence * 2, engine_id=engine_id),
            [
                record(srcaddr="192.0.2.100", dstaddr="198.51.100.100", d_pkts=1),
                record(srcaddr="192.0.2.101", dstaddr="198.51.100.101", d_pkts=2),
            ],
        )
        datagrams.append(Datagram(datagram.payload, src=src))
        texts.append(text)
    out.append(
        Case(
            "several_exporters",
            HEADER,
            "Datagrams from three exporters, one of them over IPv6, and two "
            "engines of one exporter: v5 is stateless, so each datagram is "
            "read on its own, in capture order.",
            datagrams,
            texts,
            tshark={"cflow.engine_id": ["1", "1", "2", "3"]},
        )
    )

    whole, text = packet(
        header(1, flow_sequence=1),
        [record(srcaddr="192.0.2.1", dstaddr="198.51.100.1", d_pkts=1)],
    )
    cut, _ = packet(
        header(2, flow_sequence=2),
        [record(srcaddr="192.0.2.2"), record(srcaddr="192.0.2.3")],
    )
    out.append(
        Case(
            "truncated",
            f"{HEADER}; {RECORD} (robustness)",
            "A datagram shorter than its header, one whose second record is "
            "cut short, and one of exactly 23 bytes are discarded; the "
            "whole datagram between them is read.",
            [
                Datagram(whole.payload[:12]),
                Datagram(cut.payload[:-1]),
                whole,
                Datagram(whole.payload[:23]),
            ],
            [text],
            clean=False,
        )
    )

    good, text = packet(
        header(1, flow_sequence=9),
        [record(srcaddr="192.0.2.9", dstaddr="198.51.100.9", d_pkts=9)],
    )
    others = [
        packet(header(1, version=version), [record(srcaddr="192.0.2.1")])[0]
        for version in (0, 1, 4, 6, 7, 8, 11, 0x0500)
    ]
    out.append(
        Case(
            "other_versions",
            f'{HEADER}, "version"',
            "Datagrams laid out as v5 but announcing versions 0, 1, 4, 6, 7, "
            "8, 11 and 0x0500 are not v5 and are discarded; the v5 datagram "
            "after them is read.",
            [*others, good],
            [text],
            clean=False,
        )
    )

    return out
