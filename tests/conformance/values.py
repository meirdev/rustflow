"""Field values of NetFlow v9 and IPFIX records: each as the bytes the
exporter sends and as the text the collector is expected to print.

The text follows RFC 7373: integers, floats and booleans as JSON's own,
addresses and timestamps as strings (sections 4.8 to 4.11), octet arrays
as hexadecimal (section 4.1), timestamps in UTC without an offset
(section 4.8). Element names are IANA's, from the IPFIX Information
Elements registry.
"""

import ipaddress
import struct

from wire import Pair, mac, sint, uint

def U(value: int, length: int) -> Pair:
    """An unsigned integer in `length` bytes."""
    return Pair(uint(value, length), value)


def S(value: int, length: int) -> Pair:
    """A signed integer in `length` bytes, two's complement."""
    return Pair(sint(value, length), value)


def F32(value: float) -> Pair:
    return Pair(struct.pack(">f", value), value)


def F64(value: float) -> Pair:
    return Pair(struct.pack(">d", value), value)


def IP(address: str) -> Pair:
    parsed = ipaddress.ip_address(address)
    return Pair(parsed.packed, str(parsed))


def MAC(address: str) -> Pair:
    return Pair(mac(address), address)


def HEX(data: bytes | str) -> Pair:
    """Octets the collector has no better reading of."""
    data = bytes.fromhex(data) if isinstance(data, str) else data
    return Pair(data, data.hex())


def STR(text: str, length: int | None = None) -> Pair:
    """A UTF-8 string, padded with NULs to `length` bytes if given. The
    padding is part of the value as printed."""
    encoded = text.encode()
    if length is not None:
        assert len(encoded) <= length
        encoded = encoded.ljust(length, b"\0")
    return Pair(encoded, encoded.decode())


def record(names: list[str], values: list[Pair]) -> Pair:
    """A data record: the values in template order on the wire, and a map
    from element name to value as text. An element the record holds more
    than once maps to the array of its values."""
    assert len(names) == len(values), (names, values)
    text: dict = {}
    seen: dict[str, int] = {}
    for name, value in zip(names, values):
        seen[name] = seen.get(name, 0) + 1
        if seen[name] == 1:
            text[name] = value.text
        elif seen[name] == 2:
            text[name] = [text[name], value.text]
        else:
            text[name].append(value.text)
    return Pair(b"".join(value.wire for value in values), text)
