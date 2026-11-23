"""Bytes on the wire and the capture file around them.

Nothing here knows about rustflow: the encoders follow the protocol
specifications, and the pcap writer follows the libpcap file format.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flows import common_flows

COLLECTOR_V4 = "198.51.100.1"
COLLECTOR_V6 = "2001:db8:ffff::1"
CAPTURE_START = 1_700_000_000


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def uint(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def sint(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big", signed=True)


def ip(address: str) -> bytes:
    return ipaddress.ip_address(address).packed


def mac(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


@dataclass(frozen=True)
class Pair:
    """A value twice over: as the exporter sends it, and as the collector is
    expected to print it."""

    wire: bytes
    text: Any


@dataclass(frozen=True)
class Datagram:
    payload: bytes
    src: str = "192.0.2.1"
    src_port: int = 49152
    dst_port: int = 2055


@dataclass
class Case:
    """One capture and what a collector must make of it.

    `expected` is the packets `rustflow collect --format raw` prints, in
    capture order; a datagram that must be discarded has no entry.
    `tshark` maps Wireshark field names to every value the field takes in
    the capture, in order: a second, unrelated reading of the same bytes.
    `clean` says Wireshark must find nothing malformed in the capture.
    `flows` is the common flows `rustflow collect --format common` prints,
    which `case` derives from `expected` (see flows.py).
    `deviation` says why rustflow is known not to give `expected`.
    """

    name: str
    reference: str
    description: str
    datagrams: list[Datagram]
    expected: list[dict]
    tshark: dict[str, list[str]] = field(default_factory=dict)
    clean: bool = True
    flows: list[dict] = field(default_factory=list)
    deviation: str | None = None


def case(name, reference, description, packets, **kwargs) -> Case:
    """A case from its datagrams in capture order, each with the packet the
    collector prints for it, or `None` for one it must discard."""
    received = [
        (CAPTURE_START + i, datagram.src, text)
        for i, (datagram, text) in enumerate(packets)
        if text is not None
    ]
    return Case(
        name,
        reference,
        description,
        [datagram for datagram, _ in packets],
        [text for _, _, text in received],
        flows=common_flows(received),
        **kwargs,
    )


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(datagram: Datagram) -> bytes:
    """The datagram in UDP, IP and Ethernet, with valid checksums."""
    src = ipaddress.ip_address(datagram.src)
    udp_length = 8 + len(datagram.payload)
    ports = u16(datagram.src_port) + u16(datagram.dst_port) + u16(udp_length)
    if src.version == 4:
        dst = ipaddress.ip_address(COLLECTOR_V4)
        pseudo = src.packed + dst.packed + u16(17) + u16(udp_length)
        ether_type = 0x0800
    else:
        dst = ipaddress.ip_address(COLLECTOR_V6)
        pseudo = src.packed + dst.packed + u32(udp_length) + u32(17)
        ether_type = 0x86DD
    udp_checksum = _checksum(pseudo + ports + u16(0) + datagram.payload) or 0xFFFF
    udp = ports + u16(udp_checksum) + datagram.payload

    if src.version == 4:
        header = (
            bytes([0x45, 0])
            + u16(20 + len(udp))
            + u16(0)
            + u16(0x4000)
            + bytes([64, 17])
        )
        addresses = src.packed + dst.packed
        packet = header + u16(_checksum(header + u16(0) + addresses)) + addresses + udp
    else:
        packet = u32(0x6000_0000) + u16(len(udp)) + bytes([17, 64])
        packet += src.packed + dst.packed + udp

    ethernet = mac("02:00:00:00:00:02") + mac("02:00:00:00:00:01") + u16(ether_type)
    return ethernet + packet


def write_pcap(path: Path, datagrams: list[Datagram]) -> None:
    """A classic pcap file of Ethernet frames, one second apart."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, datagram in enumerate(datagrams):
        data = frame(datagram)
        out += struct.pack("<IIII", CAPTURE_START + i, 0, len(data), len(data))
        out += data
    path.write_bytes(out)
