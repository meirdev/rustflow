"""Hand-built captures for the corners of RFC 3954 (NetFlow v9), RFC 7011
(IPFIX) and RFC 6313 (structured data) where Wireshark is no oracle:
withdrawals, reduced-size encodings, variable length, padding, malformed
lengths, reserved ids. Each test builds the datagrams with `build.py`,
replays them with `--format raw` and asserts on what came out. Behaviour on
malformed input is pinned too, so a change in it is deliberate."""

import json
import struct
from pathlib import Path

import pytest

from build import *
from oracle import keep_duplicates

T256 = (256, [(8, 4), (12, 4), (1, 4)])  # sourceIPv4Address, destinationIPv4Address, octetDeltaCount
V320 = (320, [(8, 4), (1, 4)])


def flow(src: str, dst: str, octets: int) -> bytes:
    return ip4(src) + ip4(dst) + u(octets, 4)


@pytest.fixture
def replay(collect, tmp_path: Path):
    """Raw messages for a list of datagrams: `[{version, ..., sets|flow_sets}]`.
    Repeated keys in a record are kept with a ` #n` suffix."""

    def run(payloads: list[bytes], port: int = IPFIX_PORT) -> list[dict]:
        pcap = write_pcap(tmp_path / "edge.pcap", payloads, port)
        out = collect(pcap, "--flow-type", "netflow", "--format", "raw", "--serialization", "ndjson")
        return [json.loads(line, object_pairs_hook=keep_duplicates) for line in out.decode().splitlines()]

    return run


def sets(message: dict) -> list[dict]:
    return message.get("sets", message.get("flow_sets"))


def records(message: dict, set_id: int) -> list:
    """Records of the first set with that id."""
    return next(s["records"] for s in sets(message) if s["id"] == set_id)


# ------------------------------------------------------------ IPFIX templates

def test_data_before_template_is_kept_as_an_empty_set(replay):
    out = replay([
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 100)])], seq=1),
        ipfix_message([template_set([T256])], seq=2),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 100)])], seq=3),
    ])
    assert records(out[0], 256) == []
    assert records(out[2], 256) == [{"sourceIPv4Address": "10.0.0.1", "destinationIPv4Address": "10.0.0.2", "octetDeltaCount": 100}]


def test_template_withdrawal_and_withdraw_all(replay):
    """RFC 7011 section 8.1: a template record with no fields withdraws that
    template; template id 2 with no fields withdraws every template."""
    out = replay([
        ipfix_message([template_set([T256, (257, [(7, 2), (11, 2)])])], seq=1),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 1)]), data_set(257, [u(80, 2) + u(1, 2)])], seq=2),
        ipfix_message([template_set([(256, [])])], seq=3),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 2)]), data_set(257, [u(81, 2) + u(1, 2)])], seq=4),
        ipfix_message([template_set([(2, [])])], seq=5),
        ipfix_message([data_set(257, [u(82, 2) + u(1, 2)])], seq=6),
    ])
    assert records(out[1], 256) and records(out[1], 257) == [{"sourceTransportPort": 80, "destinationTransportPort": 1}]
    assert records(out[2], 2) == [{"template_id": 256, "field_count": 0, "fields": []}]
    assert records(out[3], 256) == []
    assert records(out[3], 257) == [{"sourceTransportPort": 81, "destinationTransportPort": 1}]
    assert records(out[5], 257) == []


def test_template_redefinition_uses_the_new_fields(replay):
    out = replay([
        ipfix_message([template_set([T256])], seq=1),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 1)])], seq=2),
        ipfix_message([template_set([(256, [(2, 4)])])], seq=3),
        ipfix_message([data_set(256, [u(77, 4)])], seq=4),
    ])
    assert records(out[1], 256) == [{"sourceIPv4Address": "10.0.0.1", "destinationIPv4Address": "10.0.0.2", "octetDeltaCount": 1}]
    assert records(out[3], 256) == [{"packetDeltaCount": 77}]


def test_templates_are_scoped_by_observation_domain(replay):
    out = replay([
        ipfix_message([template_set([T256])], seq=1, odid=1),
        ipfix_message([template_set([(256, [(2, 4)])])], seq=1, odid=2),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 1)])], seq=2, odid=1),
        ipfix_message([data_set(256, [u(5, 4)])], seq=2, odid=2),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 1)])], seq=2, odid=3),
    ])
    assert records(out[2], 256)[0]["octetDeltaCount"] == 1
    assert records(out[3], 256) == [{"packetDeltaCount": 5}]
    assert records(out[4], 256) == []


def test_options_template_scope_fields_are_decoded(replay):
    out = replay([
        ipfix_message([options_template_set(257, scope=[(144, 4)], options=[(34, 4), (36, 2)])], seq=1),
        ipfix_message([data_set(257, [u(9, 4) + u(1000, 4) + u(60, 2)])], seq=2),
    ])
    template = records(out[0], 3)[0]
    assert (template["template_id"], template["field_count"], template["scope_field_count"]) == (257, 3, 1)
    assert records(out[1], 257) == [{"exportingProcessId": 9, "samplingInterval": 1000, "flowActiveTimeout": 60}]


def test_options_template_with_zero_scope_fields_is_accepted(replay):
    """RFC 7011 says the scope count MUST be greater than 0; we are lenient."""
    out = replay([
        ipfix_message([options_template_set(257, scope=[], options=[(34, 4)])], seq=1),
        ipfix_message([data_set(257, [u(1000, 4)])], seq=2),
    ])
    assert records(out[1], 257) == [{"samplingInterval": 1000}]


def test_reserved_template_id_skips_only_that_template(replay):
    """Template ids 0-255 are reserved; the templates after one in the same
    set are still installed."""
    out = replay([
        ipfix_message([template_set([(100, [(7, 2)]), T256])], seq=1),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 3)])], seq=2),
    ])
    assert [t["template_id"] for t in records(out[0], 2)] == [100, 256]
    assert records(out[1], 256)[0]["octetDeltaCount"] == 3


def test_truncated_template_record_drops_its_set_only(replay):
    out = replay([
        ipfix_message([ipfix_set(2, struct.pack("!HH", 256, 5) + field_spec(8, 4)), template_set([(257, [(7, 2)])])], seq=1),
        ipfix_message([data_set(257, [u(80, 2), u(81, 2)])], seq=2),
    ])
    assert [len(s["records"]) for s in sets(out[0])] == [0, 1]
    assert records(out[1], 257) == [{"sourceTransportPort": 80}, {"sourceTransportPort": 81}]


# ------------------------------------------------------------ IPFIX values

def test_reduced_size_encoding(replay):
    """RFC 7011 section 6.2: integers and floats may be sent narrower than
    their abstract type."""
    out = replay([
        ipfix_message([template_set([(256, [(1, 4), (1, 3), (1, 2), (1, 1), (1, 6), (2, 8), (311, 4), (311, 8)])])], seq=1),
        ipfix_message([data_set(256, [u(0xDEADBEEF, 4) + u(0x010000, 3) + u(0xBEEF, 2) + u(0xEF, 1) + u(2**40 + 1, 6) + u(2**40, 8) + struct.pack("!f", 0.25) + struct.pack("!d", 0.125)])], seq=2),
    ])
    assert records(out[1], 256) == [{
        "octetDeltaCount": 0xDEADBEEF, "octetDeltaCount #2": 65536, "octetDeltaCount #3": 0xBEEF, "octetDeltaCount #4": 0xEF, "octetDeltaCount #5": 2**40 + 1,
        "packetDeltaCount": 2**40, "samplingProbability": 0.25, "samplingProbability #2": 0.125,
    }]


def test_reduced_size_signed_values_keep_their_sign(replay):
    out = replay([
        ipfix_message([template_set([(256, [(434, 2), (434, 1), (434, 3), (434, 8)])])], seq=1),
        ipfix_message([data_set(256, [b"\xff\xfe" + b"\x80" + b"\xff\xff\xff" + u(2**63 + 5, 8)])], seq=2),
    ])
    assert list(records(out[1], 256)[0].values()) == [-2, -128, -1, -(2**63) + 5]


def test_oversize_field_length_is_tolerated(replay):
    """An unsigned32 sent in 8 bytes is not valid, but the value is unambiguous."""
    out = replay([
        ipfix_message([template_set([(256, [(10, 8), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [u(5, 8) + u(80, 2)])], seq=2),
    ])
    assert records(out[1], 256) == [{"ingressInterface": 5, "sourceTransportPort": 80}]


def test_boolean_encoding(replay):
    """RFC 7011 section 6.1.3: 1 is true, 2 is false; anything else is ignored
    and the record survives."""
    out = replay([
        ipfix_message([template_set([(256, [(276, 1), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [b"\x01" + u(80, 2), b"\x02" + u(81, 2), b"\x00" + u(82, 2)], pad=0)], seq=2),
    ])
    assert [(r["dataRecordsReliability"], r["sourceTransportPort"]) for r in records(out[1], 256)] == [(True, 80), (False, 81), (None, 82)]


def test_variable_length_fields(replay):
    """RFC 7011 section 7: one length byte, or 255 and two; zero length is legal."""
    long = b"x" * 300
    out = replay([
        ipfix_message([template_set([(256, [(82, 0xFFFF), (83, 0xFFFF), (82, 0xFFFF), (315, 0xFFFF)])])], seq=1),
        ipfix_message([data_set(256, [var(b"eth0") + var(b"") + var(long) + var(bytes.fromhex("0102ff"))])], seq=2),
    ])
    assert records(out[1], 256) == [{"interfaceName": "eth0", "interfaceDescription": "", "interfaceName #2": long.decode(), "dataLinkFrameSection": "0102ff"}]


def test_variable_length_overrun_drops_the_record(replay):
    out = replay([
        ipfix_message([template_set([(256, [(82, 0xFFFF), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [bytes([50]) + b"abc" + u(80, 2)])], seq=2),
        ipfix_message([data_set(256, [var(b"eth1") + u(81, 2)])], seq=3),
    ])
    assert records(out[1], 256) == []
    assert records(out[2], 256) == [{"interfaceName": "eth1", "sourceTransportPort": 81}]


def test_ill_formed_utf8_is_ignored_not_fatal(replay):
    """RFC 7011 section 6.1.6: the collector ignores the value; the record
    and the ones after it are kept."""
    out = replay([
        ipfix_message([template_set([(256, [(82, 0xFFFF), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [var(b"\xff\xfe") + u(80, 2), var(b"ok") + u(81, 2)])], seq=2),
    ])
    assert records(out[1], 256) == [{"interfaceName": None, "sourceTransportPort": 80}, {"interfaceName": "ok", "sourceTransportPort": 81}]


def test_fixed_length_string_padding_is_stripped(replay):
    out = replay([
        ipfix_message([template_set([(256, [(82, 10)])])], seq=1),
        ipfix_message([data_set(256, [b"no" + b"\0" * 8])], seq=2),
    ])
    assert records(out[1], 256) == [{"interfaceName": "no"}]


def test_datetime_encodings(replay):
    """Seconds, milliseconds, and NTP-format micro/nanoseconds (RFC 7011 sections 6.1.7-6.1.10)."""
    out = replay([
        ipfix_message([template_set([(256, [(150, 4), (152, 8), (154, 8), (156, 8)])])], seq=1),
        ipfix_message([data_set(256, [u(1700000000, 4) + u(1700000000123, 8) + ntp(1700000000, 0.5) + ntp(1700000000, 0.75)])], seq=2),
    ])
    assert records(out[1], 256) == [{
        "flowStartSeconds": "2023-11-14T22:13:20Z", "flowStartMilliseconds": "2023-11-14T22:13:20.123Z",
        "flowStartMicroseconds": "2023-11-14T22:13:20.500Z", "flowStartNanoseconds": "2023-11-14T22:13:20.750Z",
    }]


def test_address_types(replay):
    out = replay([
        ipfix_message([template_set([(256, [(27, 16), (56, 6), (8, 4)])])], seq=1),
        ipfix_message([data_set(256, [ip6("2001:db8::1") + mac("00:11:22:aa:bb:cc") + ip4("192.0.2.1")])], seq=2),
    ])
    record = records(out[1], 256)[0]
    assert (record["sourceIPv6Address"], record["sourceMacAddress"].lower(), record["sourceIPv4Address"]) == ("2001:db8::1", "00:11:22:aa:bb:cc", "192.0.2.1")


def test_enterprise_and_unknown_elements_keep_their_bytes(replay):
    out = replay([
        ipfix_message([template_set([(256, [(100, 4, 29305), (30000, 3), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [u(0x01020304, 4) + b"\x01\x02\x03" + u(443, 2)])], seq=2),
    ])
    fields = records(out[0], 2)[0]["fields"]
    assert (fields[0]["enterprise_bit"], fields[0]["enterprise_number"], fields[1]["enterprise_number"]) == (True, 29305, None)
    assert records(out[1], 256) == [{"100": "01020304", "30000": "010203", "sourceTransportPort": 443}]


# ------------------------------------------------------------ IPFIX structured data (RFC 6313)

def test_basic_list(replay):
    out = replay([
        ipfix_message([template_set([(256, [(291, 0xFFFF), (7, 2)])])], seq=1),
        ipfix_message([data_set(256, [var(u(3, 1) + struct.pack("!HH", 8, 4) + ip4("10.1.1.1") + ip4("10.1.1.2")) + u(80, 2)])], seq=2),
    ])
    record = records(out[1], 256)[0]
    assert record["basicList"]["semantic"] == "AllOf"
    assert record["basicList"]["content"] == ["10.1.1.1", "10.1.1.2"]
    assert record["sourceTransportPort"] == 80


def test_sub_template_list_known_and_unknown_template(replay):
    out = replay([
        ipfix_message([template_set([(256, [(292, 0xFFFF), (7, 2)]), (257, [(8, 4)])])], seq=1),
        ipfix_message([data_set(256, [
            var(u(3, 1) + struct.pack("!H", 257) + ip4("10.1.1.1") + ip4("10.1.1.2")) + u(80, 2),
            var(u(3, 1) + struct.pack("!H", 258) + ip4("10.1.1.1")) + u(81, 2),
        ])], seq=2),
    ])
    known, unknown = records(out[1], 256)
    assert known["subTemplateList"] == {"semantic": "AllOf", "template_id": 257, "data": [{"sourceIPv4Address": "10.1.1.1"}, {"sourceIPv4Address": "10.1.1.2"}]}
    assert unknown["subTemplateList"] == {"semantic": "AllOf", "template_id": 258, "data": []}
    assert (known["sourceTransportPort"], unknown["sourceTransportPort"]) == (80, 81)


def test_sub_template_multi_list(replay):
    body = struct.pack("!HH", 257, 12) + ip4("10.2.2.1") + ip4("10.2.2.2") + struct.pack("!HH", 258, 6) + u(443, 2)
    out = replay([
        ipfix_message([template_set([(256, [(293, 0xFFFF)]), (257, [(8, 4)]), (258, [(7, 2)])])], seq=1),
        ipfix_message([data_set(256, [var(u(3, 1) + body)])], seq=2),
    ])
    assert records(out[1], 256)[0]["subTemplateMultiList"] == {"semantic": "AllOf", "data": [
        {"template_id": 257, "length": 12, "data": [{"sourceIPv4Address": "10.2.2.1"}, {"sourceIPv4Address": "10.2.2.2"}]},
        {"template_id": 258, "length": 6, "data": [{"sourceTransportPort": 443}]},
    ]}


# ------------------------------------------------------------ IPFIX framing

def test_set_padding_and_multiple_records(replay):
    """RFC 7011 section 3.3.1: padding shorter than a record is allowed after
    the records of a set, and after the templates."""
    out = replay([
        ipfix_message([template_set([(256, [(7, 2), (11, 2), (4, 1)]), (257, [(7, 2)])], pad=2), data_set(256, [u(1, 2) + u(2, 2) + u(6, 1), u(3, 2) + u(4, 2) + u(17, 1)], pad=2), data_set(257, [u(i, 2) for i in range(4)])], seq=1),
    ])
    assert records(out[0], 256) == [{"sourceTransportPort": 1, "destinationTransportPort": 2, "protocolIdentifier": 6}, {"sourceTransportPort": 3, "destinationTransportPort": 4, "protocolIdentifier": 17}]
    assert [r["sourceTransportPort"] for r in records(out[0], 257)] == [0, 1, 2, 3]


def test_partial_trailing_record_is_ignored(replay):
    out = replay([
        ipfix_message([template_set([T256])], seq=1),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 1), ip4("10.0.0.3") + ip4("10.0.0.4")], pad=0)], seq=2),
    ])
    assert len(records(out[1], 256)) == 1


@pytest.mark.parametrize("length", [0, 2, 3])
def test_set_length_shorter_than_its_header_ends_the_message(replay, length):
    """The sets before it are kept; the bytes after it are not re-read as sets."""
    out = replay([
        ipfix_message([template_set([T256])], seq=1),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 8)]), struct.pack("!HH", 256, length) + flow("10.0.0.1", "10.0.0.2", 1)], seq=2),
        ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 9)])], seq=3),
    ])
    assert [s["id"] for s in sets(out[1])] == [256]
    assert records(out[1], 256)[0]["octetDeltaCount"] == 8
    assert records(out[2], 256)[0]["octetDeltaCount"] == 9


def test_reserved_set_id_is_skipped(replay):
    out = replay([
        ipfix_message([template_set([T256])], seq=1),
        ipfix_message([ipfix_set(100, b"\x01\x02\x03\x04"), data_set(256, [flow("10.0.0.1", "10.0.0.2", 3)])], seq=2),
    ])
    assert [(s["id"], len(s["records"])) for s in sets(out[1])] == [(100, 0), (256, 1)]


def test_message_length_shorter_than_its_sets(replay):
    """The message length bounds the sets; what follows is not parsed."""
    header_only = struct.pack("!HHIII", 10, 16, 1700000000, 2, 1) + data_set(256, [flow("10.0.0.1", "10.0.0.2", 6)])
    out = replay([ipfix_message([template_set([T256])], seq=1), header_only, ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 7)])], seq=3)])
    assert sets(out[1]) == []
    assert records(out[2], 256)[0]["octetDeltaCount"] == 7


def test_message_length_longer_than_the_datagram_is_dropped(replay):
    too_long = struct.pack("!HHIII", 10, 200, 1700000000, 2, 1) + data_set(256, [flow("10.0.0.1", "10.0.0.2", 5)])
    out = replay([ipfix_message([template_set([T256])], seq=1), too_long, ipfix_message([data_set(256, [flow("10.0.0.1", "10.0.0.2", 7)])], seq=3)])
    assert [m["sequence_number"] for m in out] == [1, 3]


# ------------------------------------------------------------ NetFlow v9

def test_v9_data_before_template(replay):
    out = replay([
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(1, 4)])], count=1, seq=1),
        v9_message([v9_template_flowset([V320])], count=1, seq=2),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(1, 4)])], count=1, seq=3),
    ], NETFLOW_PORT)
    assert records(out[0], 320) == []
    assert records(out[2], 320) == [{"sourceIPv4Address": "10.0.0.1", "octetDeltaCount": 1}]


def test_v9_templates_are_scoped_by_source_id(replay):
    out = replay([
        v9_message([v9_template_flowset([V320])], count=1, seq=1, source_id=1),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(1, 4)])], count=1, seq=1, source_id=2),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(1, 4)])], count=1, seq=2, source_id=1),
    ], NETFLOW_PORT)
    assert records(out[1], 320) == []
    assert records(out[2], 320) == [{"sourceIPv4Address": "10.0.0.1", "octetDeltaCount": 1}]


def test_v9_two_templates_in_one_flowset_and_padding(replay):
    """RFC 3954 section 5: FlowSets are padded to a 32-bit boundary."""
    out = replay([
        v9_message([v9_template_flowset([V320, (321, [(7, 2), (4, 1)])], pad=2)], count=2, seq=1),
        v9_message([v9_data_flowset(321, [u(1, 2) + u(6, 1), u(2, 2) + u(17, 1)], pad=2)], count=2, seq=2),
    ], NETFLOW_PORT)
    assert [t["id"] for t in records(out[0], 0)] == [320, 321]
    assert records(out[1], 321) == [{"sourceTransportPort": 1, "protocolIdentifier": 6}, {"sourceTransportPort": 2, "protocolIdentifier": 17}]


def test_v9_options_template_scope_and_padding(replay):
    """RFC 3954 section 6.1: scope and option lengths are in bytes, and the
    options template FlowSet is padded to 32 bits."""
    out = replay([
        v9_message([v9_options_template_flowset(576, scope=[(1, 4)], options=[(34, 4), (36, 2)], pad=2)], count=1, seq=1),
        v9_message([v9_data_flowset(576, [u(9, 4) + u(1000, 4) + u(60, 2)])], count=1, seq=2),
    ], NETFLOW_PORT)
    template = records(out[0], 1)[0]
    assert (template["option_scope_length"], template["option_length"], template["scope_fields"]) == (4, 8, [{"type": "System", "length": 4}])
    assert records(out[1], 576) == [{"System": 9, "samplingInterval": 1000, "flowActiveTimeout": 60}]


def test_v9_odd_field_lengths_and_unknown_types(replay):
    """Exporters send integers in 3 bytes or wider than the type; unknown
    field types keep their bytes."""
    out = replay([
        v9_message([v9_template_flowset([(322, [(1, 8), (1, 3), (1, 2), (2, 1), (60000, 3), (8, 4)])])], count=1, seq=1),
        v9_message([v9_data_flowset(322, [u(2**40, 8) + u(65536, 3) + u(500, 2) + u(7, 1) + b"\xaa\xbb\xcc" + ip4("10.0.0.9")])], count=1, seq=2),
    ], NETFLOW_PORT)
    assert records(out[1], 322) == [{"octetDeltaCount": 2**40, "octetDeltaCount #2": 65536, "octetDeltaCount #3": 500, "packetDeltaCount": 7, "60000": "aabbcc", "sourceIPv4Address": "10.0.0.9"}]


def test_v9_zero_length_field_is_null(replay):
    out = replay([
        v9_message([v9_options_template_flowset(576, scope=[(1, 0)], options=[(34, 4)])], count=1, seq=1),
        v9_message([v9_data_flowset(576, [u(1000, 4)])], count=1, seq=2),
    ], NETFLOW_PORT)
    assert records(out[1], 576) == [{"System": None, "samplingInterval": 1000}]


def test_v9_flowset_length_shorter_than_its_header_ends_the_packet(replay):
    out = replay([
        v9_message([v9_template_flowset([V320])], count=1, seq=1),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(8, 4)]), struct.pack("!HH", 320, 0) + ip4("10.0.0.1") + u(1, 4)], count=2, seq=2),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(9, 4)])], count=1, seq=3),
    ], NETFLOW_PORT)
    assert [s["id"] for s in sets(out[1])] == [320]
    assert records(out[1], 320)[0]["octetDeltaCount"] == 8
    assert records(out[2], 320)[0]["octetDeltaCount"] == 9


def test_v9_reserved_flowset_id_is_skipped(replay):
    out = replay([
        v9_message([v9_template_flowset([V320])], count=1, seq=1),
        v9_message([v9_flowset(100, b"\x01\x02\x03\x04"), v9_data_flowset(320, [ip4("10.0.0.1") + u(3, 4)])], count=1, seq=2),
    ], NETFLOW_PORT)
    assert [(s["id"], len(s["records"])) for s in sets(out[1])] == [(100, 0), (320, 1)]


def test_v9_truncated_header_is_dropped(replay):
    out = replay([
        v9_message([v9_template_flowset([V320])], count=1, seq=1),
        struct.pack("!HH", 9, 1),
        v9_message([v9_data_flowset(320, [ip4("10.0.0.1") + u(9, 4)])], count=1, seq=3),
    ], NETFLOW_PORT)
    assert [m["sequence_number"] for m in out] == [1, 3]
