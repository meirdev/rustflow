"""Hand-built sFlow v5 datagrams (sflow_version_5.txt, sflow_drops.txt) for
the corners the sanity capture does not reach: expanded samples, the
sampled IPv4/IPv6/Ethernet records, extended gateway, IPv6 agents, unknown
enterprise records and sample formats, drop samples, and malformed
lengths. Raw output pins the structure, common output pins the conversion."""

import json
import struct
from pathlib import Path

import pytest

from build import *

STAMPS = ("time_received_ns", "time_flow_start_ns", "time_flow_end_ns")


def eth_ip_tcp(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0xB8, 40, 0x1111, 0x4000, 64, 6, 0, ip4(src), ip4(dst))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 8192, 0, 0)
    return mac("02:00:00:00:00:02") + mac("02:00:00:00:00:01") + b"\x08\x00" + ip + tcp


FRAME = eth_ip_tcp()
HEADER = raw_packet_header(FRAME)


@pytest.fixture
def replay(collect, tmp_path: Path):
    def run(datagrams: list[bytes], fmt: str = "raw") -> list[dict]:
        pcap = write_pcap(tmp_path / "sflow.pcap", datagrams, SFLOW_PORT)
        out = collect(pcap, "--flow-type", "sflow", "--format", fmt, "--serialization", "ndjson")
        messages = [json.loads(line) for line in out.decode().splitlines()]
        if fmt == "common":
            return [{k: v for k, v in m.items() if v is not None and k not in STAMPS} for m in messages]
        return messages

    return run


def sample_kinds(datagram: dict) -> list[str]:
    return [next(iter(s)) for s in datagram["samples"]]


# ------------------------------------------------------------ conversion

def test_flow_sample_with_header_switch_and_router(replay):
    [flow] = replay([sflow_datagram([flow_sample([HEADER, extended_switch(100, 0, 200, 0), extended_router("203.0.113.1", 24, 22)])])], "common")
    assert flow == {
        "flow_type": "SFLOW_V5", "sequence_num": 1, "sampling_rate": 2000, "sampler_address": "192.0.2.10", "bytes": 58, "packets": 1,
        "src_addr": "10.0.0.1", "dst_addr": "10.0.0.2", "src_mac": "02:00:00:00:00:01", "dst_mac": "02:00:00:00:00:02", "etype": 0x0800,
        "proto": 6, "src_port": 1234, "dst_port": 80, "in_if": 3, "out_if": 4, "ip_tos": 0xB8, "ip_ttl": 64, "tcp_flags": 0x18,
        "fragment_id": 0x1111, "fragment_offset": 0, "next_hop": "203.0.113.1", "src_net": 24, "dst_net": 22, "src_vlan": 100, "dst_vlan": 200,
    }


def test_expanded_flow_sample_carries_wide_interface_indexes(replay):
    [raw] = replay([sflow_datagram([expanded_flow_sample([HEADER], source_index=70000, input_if=(0, 70000), output_if=(2, 5))])])
    expanded = raw["samples"][0]["ExpandedFlow"]
    assert (expanded["header"]["source_id_value"], expanded["input_if_value"], expanded["output_if_format"], expanded["output_if_value"]) == (70000, 70000, 2, 5)
    [flow] = replay([sflow_datagram([expanded_flow_sample([HEADER], input_if=(0, 70000), output_if=(0, 70001))])], "common")
    assert (flow["in_if"], flow["out_if"], flow["src_addr"]) == (70000, 70001, "10.0.0.1")


def test_ipv6_agent_address(replay):
    [flow] = replay([sflow_datagram([flow_sample([HEADER])], agent="2001:db8::10")], "common")
    assert flow["sampler_address"] == "2001:db8::10"


def test_sampled_ipv4_record(replay):
    [flow] = replay([sflow_datagram([flow_sample([sampled_ipv4("10.1.1.1", "10.1.1.2", proto=6, sport=1234, dport=80, tcp_flags=0x10, tos=0xB8, length=100)])])], "common")
    assert {k: flow[k] for k in ("bytes", "packets", "src_addr", "dst_addr", "etype", "proto", "src_port", "dst_port", "tcp_flags", "ip_tos")} == {
        "bytes": 100, "packets": 1, "src_addr": "10.1.1.1", "dst_addr": "10.1.1.2", "etype": 0x0800, "proto": 6, "src_port": 1234, "dst_port": 80, "tcp_flags": 0x10, "ip_tos": 0xB8,
    }


def test_sampled_ipv6_record(replay):
    [flow] = replay([sflow_datagram([flow_sample([sampled_ipv6("2001:db8::1", "2001:db8::2", proto=17, sport=1234, dport=53)])])], "common")
    assert {k: flow[k] for k in ("src_addr", "dst_addr", "etype", "proto", "src_port", "dst_port")} == {
        "src_addr": "2001:db8::1", "dst_addr": "2001:db8::2", "etype": 0x86DD, "proto": 17, "src_port": 1234, "dst_port": 53,
    }


def test_sampled_ethernet_record(replay):
    [flow] = replay([sflow_datagram([flow_sample([sampled_ethernet("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800, length=64)])])], "common")
    assert (flow["src_mac"].lower(), flow["dst_mac"].lower(), flow["etype"], flow["bytes"], flow["packets"]) == ("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800, 64, 1)


def test_extended_gateway(replay):
    gateway = extended_gateway("203.0.113.9", as_=65001, src_as=65002, src_peer_as=65003, as_path=[(2, [65010, 65020])], communities=[65001 << 16 | 100], localpref=200)
    [raw] = replay([sflow_datagram([flow_sample([HEADER, gateway])])])
    data = raw["samples"][0]["Flow"]["records"][1]["data"]["ExtendedGateway"]
    assert (data["nexthop"], data["as"], data["src_as"], data["src_peer_as"], data["communities"], data["localpref"]) == ("203.0.113.9", 65001, 65002, 65003, [65001 << 16 | 100], 200)
    [flow] = replay([sflow_datagram([flow_sample([HEADER, gateway])])], "common")
    assert (flow["src_as"], flow["dst_as"], flow["bgp_next_hop"]) == (65002, 65020, "203.0.113.9")


def test_raw_header_of_ip_protocol(replay):
    """header_protocol 11 (IPv4): the sampled bytes start at the IP header."""
    [flow] = replay([sflow_datagram([flow_sample([raw_packet_header(FRAME[14:], protocol=11)])])], "common")
    assert (flow["etype"], flow["src_addr"], flow["dst_port"], "src_mac" in flow) == (0x0800, "10.0.0.1", 80, False)


def test_zero_sampling_rate_passes_through(replay):
    [flow] = replay([sflow_datagram([flow_sample([HEADER], rate=0)])], "common")
    assert flow["sampling_rate"] == 0


# ------------------------------------------------------------ unknown and mixed content

def test_unknown_enterprise_record_is_skipped(replay):
    [raw] = replay([sflow_datagram([flow_sample([sflow_record(1, b"\x01\x02\x03\x04", enterprise=4413), HEADER])])])
    records = raw["samples"][0]["Flow"]["records"]
    assert records[0]["data"] == {"Unknown": [1, 2, 3, 4]} and "SampledHeader" in records[1]["data"]
    [flow] = replay([sflow_datagram([flow_sample([sflow_record(1, b"\x01\x02\x03\x04", enterprise=4413), HEADER])])], "common")
    assert flow["src_addr"] == "10.0.0.1"


def test_unknown_sample_formats_are_kept_as_bytes(replay):
    [raw] = replay([sflow_datagram([sflow_sample(9, b"\x00" * 16), sflow_sample(1, b"\x01" * 8, enterprise=4413), flow_sample([HEADER])])])
    assert sample_kinds(raw) == ["Unknown", "Unknown", "Flow"]
    assert raw["samples"][1] == {"Unknown": [1] * 8}
    assert len(replay([sflow_datagram([sflow_sample(9, b"\x00" * 16), flow_sample([HEADER])])], "common")) == 1


def test_counter_sample_alongside_flow_sample(replay):
    [raw] = replay([sflow_datagram([counter_sample([if_counters(ifindex=3, in_octets=1000, out_octets=2000)]), flow_sample([HEADER])])])
    assert sample_kinds(raw) == ["Counter", "Flow"]
    [counters] = raw["samples"][0]["Counter"]["records"][0]["data"]
    assert (counters["IfCounters"]["if_index"], counters["IfCounters"]["if_in_octets"], counters["IfCounters"]["if_out_octets"]) == (3, 1000, 2000)
    assert len(replay([sflow_datagram([counter_sample([if_counters()]), flow_sample([HEADER])])], "common")) == 1


def test_drop_sample(replay):
    """sflow_drops.txt format 5: parsed in raw output, not a flow."""
    [raw] = replay([sflow_datagram([drop_sample([HEADER], drops=1, input_if=3, output_if=0, reason=3)])])
    drop = raw["samples"][0]["Drop"]
    assert (drop["drops"], drop["input"], drop["output"], drop["reason"]) == (1, 3, 0, "PortUnreachable")
    assert "SampledHeader" in drop["records"][0]["data"]
    assert replay([sflow_datagram([drop_sample([HEADER])])], "common") == []


# ------------------------------------------------------------ framing

def test_sample_count_in_the_header_is_not_trusted(replay):
    """Samples are parsed to the end of the datagram whatever the count says."""
    two = sflow_datagram([flow_sample([HEADER]), flow_sample([HEADER], seq=2)])
    for count in (1, 3):
        [raw] = replay([two[:16] + struct.pack("!I", count) + two[20:]])
        assert [s["Flow"]["header"]["sample_sequence_number"] for s in raw["samples"]] == [1, 2]


def test_sample_length_is_not_trusted(replay):
    [raw] = replay([sflow_datagram([flow_sample([HEADER], length=999), flow_sample([HEADER], seq=2)])])
    assert [s["Flow"]["header"]["length"] for s in raw["samples"]] == [999, 112]


def test_malformed_record_length_drops_the_datagram(replay):
    bad = sflow_datagram([flow_sample([struct.pack("!II", 1001, 8) + struct.pack("!IIII", 100, 0, 200, 0), HEADER])])
    good = sflow_datagram([flow_sample([HEADER], seq=9)])
    [raw] = replay([bad, good])
    assert raw["samples"][0]["Flow"]["header"]["sample_sequence_number"] == 9


def test_truncated_datagram_is_dropped(replay):
    whole = sflow_datagram([flow_sample([HEADER])])
    [raw] = replay([whole[:-20], sflow_datagram([flow_sample([HEADER], seq=9)])])
    assert raw["sequence_number"] == 1 and raw["samples"][0]["Flow"]["header"]["sample_sequence_number"] == 9


def test_header_length_beyond_the_record_drops_the_datagram(replay):
    lying = sflow_record(1, struct.pack("!IIII", 1, 100, 4, 200) + FRAME + b"\0\0")
    assert replay([sflow_datagram([flow_sample([lying])])]) == []


def test_other_versions_are_ignored(replay):
    v5 = sflow_datagram([flow_sample([HEADER], seq=9)])
    [raw] = replay([struct.pack("!I", 4) + v5[4:], v5])
    assert raw["samples"][0]["Flow"]["header"]["sample_sequence_number"] == 9
