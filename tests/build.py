"""Builders for hand-made NetFlow v9 and IPFIX captures, for the RFC
edge-case tests. Everything is big-endian `struct`, so a test reads like
the RFC's wire diagram."""

import socket
import struct
from pathlib import Path

IPFIX_PORT = 4739
NETFLOW_PORT = 2055


# ------------------------------------------------------------ pcap

def udp_frame(payload: bytes, dst_port: int, src="192.0.2.10", dst="192.0.2.1") -> bytes:
    udp = struct.pack("!HHHH", 40000, dst_port, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return bytes.fromhex("020000000001") + bytes.fromhex("020000000010") + b"\x08\x00" + ip + udp


def write_pcap(path: Path, payloads: list[bytes], dst_port: int) -> Path:
    """One UDP datagram per payload, a second apart."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, payload in enumerate(payloads):
            frame = udp_frame(payload, dst_port)
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)) + frame)
    return path


# ------------------------------------------------------------ IPFIX (RFC 7011)

def ipfix_message(sets: list[bytes], seq: int = 1, odid: int = 1, export_time: int = 1700000000) -> bytes:
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), export_time, seq, odid) + body


def field_spec(ie: int, length: int, pen: int | None = None) -> bytes:
    if pen is None:
        return struct.pack("!HH", ie, length)
    return struct.pack("!HHI", 0x8000 | ie, length, pen)


def ipfix_set(set_id: int, body: bytes, pad: int = 0) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(body) + pad) + body + b"\0" * pad


def template_set(templates: list[tuple[int, list[tuple]]], pad: int = 0) -> bytes:
    """Set 2. A template with no fields is a withdrawal (RFC 7011 §8.1)."""
    body = b"".join(struct.pack("!HH", tid, len(fields)) + b"".join(field_spec(*f) for f in fields) for tid, fields in templates)
    return ipfix_set(2, body, pad)


def options_template_set(tid: int, scope: list[tuple], options: list[tuple], pad: int = 0) -> bytes:
    """Set 3: field count, then scope field count (RFC 7011 §3.4.2.2)."""
    body = struct.pack("!HHH", tid, len(scope) + len(options), len(scope)) + b"".join(field_spec(*f) for f in scope + options)
    return ipfix_set(3, body, pad)


def data_set(tid: int, records: list[bytes], pad: int | None = None) -> bytes:
    body = b"".join(records)
    return ipfix_set(tid, body, (-len(body)) % 4 if pad is None else pad)


def var(value: bytes) -> bytes:
    """Variable-length field: one length byte, or 255 and two (RFC 7011 §7)."""
    if len(value) < 255:
        return bytes([len(value)]) + value
    return b"\xff" + struct.pack("!H", len(value)) + value


# ------------------------------------------------------------ NetFlow v9 (RFC 3954)

def v9_message(flowsets: list[bytes], count: int, seq: int = 1, source_id: int = 1, uptime_ms: int = 3_600_000, unix_secs: int = 1700000000) -> bytes:
    return struct.pack("!HHIIII", 9, count, uptime_ms, unix_secs, seq, source_id) + b"".join(flowsets)


def v9_flowset(flowset_id: int, body: bytes, pad: int = 0) -> bytes:
    return struct.pack("!HH", flowset_id, 4 + len(body) + pad) + body + b"\0" * pad


def v9_template_flowset(templates: list[tuple[int, list[tuple[int, int]]]], pad: int = 0) -> bytes:
    body = b"".join(struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields) for tid, fields in templates)
    return v9_flowset(0, body, pad)


def v9_options_template_flowset(tid: int, scope: list[tuple[int, int]], options: list[tuple[int, int]], pad: int = 0) -> bytes:
    """Flowset 1: scope length and option length are in bytes (RFC 3954 §6.1)."""
    body = struct.pack("!HHH", tid, 4 * len(scope), 4 * len(options)) + b"".join(struct.pack("!HH", *f) for f in scope + options)
    return v9_flowset(1, body, pad)


def v9_data_flowset(tid: int, records: list[bytes], pad: int | None = None) -> bytes:
    body = b"".join(records)
    return v9_flowset(tid, body, (-len(body)) % 4 if pad is None else pad)


# ------------------------------------------------------------ values

def u(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def ip4(text: str) -> bytes:
    return socket.inet_aton(text)


def ip6(text: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, text)


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def ntp(seconds: int, fraction: float = 0.0) -> bytes:
    """dateTimeMicroseconds/Nanoseconds: NTP seconds since 1900 and a 32-bit fraction."""
    return struct.pack("!II", seconds + 2_208_988_800, int(fraction * (1 << 32)))


# ------------------------------------------------------------ sFlow v5 (sflow_version_5.txt)

SFLOW_PORT = 6343


def sflow_datagram(samples: list[bytes], agent: str = "192.0.2.10", sub_agent_id: int = 0, seq: int = 1, uptime_ms: int = 3_600_000) -> bytes:
    address = struct.pack("!I", 1) + ip4(agent) if ":" not in agent else struct.pack("!I", 2) + ip6(agent)
    return struct.pack("!I", 5) + address + struct.pack("!III", sub_agent_id, seq, uptime_ms) + struct.pack("!I", len(samples)) + b"".join(samples)


def sflow_record(data_format: int, body: bytes, enterprise: int = 0) -> bytes:
    """A flow or counter record: (enterprise << 12 | format), length, body."""
    return struct.pack("!II", (enterprise << 12) | data_format, len(body)) + body


def sflow_sample(data_format: int, body: bytes, enterprise: int = 0, length: int | None = None) -> bytes:
    return struct.pack("!II", (enterprise << 12) | data_format, len(body) if length is None else length) + body


def flow_sample(records: list[bytes], seq: int = 1, source_id: int = 3, rate: int = 2000, pool: int = 100_000, drops: int = 0, input_if: int = 3, output_if: int = 4, length: int | None = None) -> bytes:
    body = struct.pack("!IIIIIIII", seq, source_id, rate, pool, drops, input_if, output_if, len(records)) + b"".join(records)
    return sflow_sample(1, body, length=length)


def expanded_flow_sample(records: list[bytes], seq: int = 1, source_type: int = 0, source_index: int = 3, rate: int = 2000, pool: int = 100_000, drops: int = 0, input_if: tuple[int, int] = (0, 3), output_if: tuple[int, int] = (0, 4)) -> bytes:
    body = struct.pack("!IIIIII", seq, source_type, source_index, rate, pool, drops) + struct.pack("!IIII", *input_if, *output_if) + struct.pack("!I", len(records)) + b"".join(records)
    return sflow_sample(3, body)


def counter_sample(records: list[bytes], seq: int = 1, source_id: int = 3) -> bytes:
    return sflow_sample(2, struct.pack("!III", seq, source_id, len(records)) + b"".join(records))


def drop_sample(records: list[bytes], seq: int = 1, source_class: int = 0, source_index: int = 3, drops: int = 1, input_if: int = 3, output_if: int = 0, reason: int = 3) -> bytes:
    """sflow_drops.txt, format 5."""
    return sflow_sample(5, struct.pack("!IIIIIIII", seq, source_class, source_index, drops, input_if, output_if, reason, len(records)) + b"".join(records))


def raw_packet_header(frame: bytes, protocol: int = 1, frame_length: int | None = None, stripped: int = 4) -> bytes:
    pad = (-len(frame)) % 4
    body = struct.pack("!IIII", protocol, len(frame) + stripped if frame_length is None else frame_length, stripped, len(frame)) + frame + b"\0" * pad
    return sflow_record(1, body)


def sampled_ethernet(src: str, dst: str, etype: int, length: int = 64) -> bytes:
    """Format 2: MACs are padded to 8 bytes."""
    return sflow_record(2, struct.pack("!I", length) + mac(src) + b"\0\0" + mac(dst) + b"\0\0" + struct.pack("!I", etype))


def sampled_ipv4(src: str, dst: str, proto: int = 6, sport: int = 1234, dport: int = 80, tcp_flags: int = 0x10, tos: int = 0, length: int = 100) -> bytes:
    return sflow_record(3, struct.pack("!II", length, proto) + ip4(src) + ip4(dst) + struct.pack("!IIII", sport, dport, tcp_flags, tos))


def sampled_ipv6(src: str, dst: str, proto: int = 17, sport: int = 1234, dport: int = 53, tcp_flags: int = 0, priority: int = 0, length: int = 100) -> bytes:
    return sflow_record(4, struct.pack("!II", length, proto) + ip6(src) + ip6(dst) + struct.pack("!IIII", sport, dport, tcp_flags, priority))


def extended_switch(src_vlan: int, src_pri: int, dst_vlan: int, dst_pri: int) -> bytes:
    return sflow_record(1001, struct.pack("!IIII", src_vlan, src_pri, dst_vlan, dst_pri))


def sflow_address(text: str) -> bytes:
    return struct.pack("!I", 1) + ip4(text) if ":" not in text else struct.pack("!I", 2) + ip6(text)


def extended_router(nexthop: str, src_mask: int, dst_mask: int) -> bytes:
    return sflow_record(1002, sflow_address(nexthop) + struct.pack("!II", src_mask, dst_mask))


def extended_gateway(nexthop: str, as_: int, src_as: int, src_peer_as: int, as_path: list[tuple[int, list[int]]], communities: list[int], localpref: int) -> bytes:
    path = struct.pack("!I", len(as_path)) + b"".join(struct.pack("!II", kind, len(ases)) + b"".join(struct.pack("!I", a) for a in ases) for kind, ases in as_path)
    comms = struct.pack("!I", len(communities)) + b"".join(struct.pack("!I", c) for c in communities)
    return sflow_record(1003, sflow_address(nexthop) + struct.pack("!III", as_, src_as, src_peer_as) + path + comms + struct.pack("!I", localpref))


def if_counters(ifindex: int = 3, in_octets: int = 1000, out_octets: int = 2000) -> bytes:
    return sflow_record(1, struct.pack("!IIQIIQIIIIIIQIIIIII", ifindex, 6, 10_000_000_000, 1, 3, in_octets, 10, 0, 0, 0, 0, 0, out_octets, 20, 0, 0, 0, 0, 0))
