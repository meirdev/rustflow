"""Wireshark as an oracle: for every capture, tshark's decode and
rustflow's raw output must agree, first on message headers, sets,
templates and record counts (level 1), then on every value of every
NetFlow v9/IPFIX data record and on the common flow each sFlow sampled
header implies (level 2). See `oracle.py` for the comparison rules.
Skipped when tshark is not installed.

Set `RUSTFLOW_ORACLE_PCAPS` to a directory of extra captures to include;
a file name containing `sflow` is replayed as sFlow, anything else as
NetFlow/IPFIX. Only their first `ORACLE_LIMIT` packets are compared. A
`captures.json` in that directory overrides those defaults per file:

    {"meir.pcap": {"port": 8008}, "big.pcap": {"limit": 500, "flow_type": "sflow"}}

`port` tells tshark which UDP port to decode as NetFlow/IPFIX or sFlow;
rustflow decodes every UDP payload of a capture whatever its port.
"""

import json
import os
from pathlib import Path

import pytest

import oracle

ORACLE_LIMIT = 2000

FIXTURES = [
    ("netflow_v5_sanity.pcap", "netflow"),
    ("netflow_v9_sanity.pcap", "netflow"),
    ("ipfix_sanity.pcap", "netflow"),
    ("sflow_v5_sanity.pcap", "sflow"),
]


def captures() -> list:
    cases = [pytest.param(Path(__file__).parent / "fixtures" / "pcap" / name, flow_type, None, None, id=name) for name, flow_type in FIXTURES]
    extra = os.environ.get("RUSTFLOW_ORACLE_PCAPS")
    if extra:
        manifest = Path(extra) / "captures.json"
        overrides = json.loads(manifest.read_text()) if manifest.is_file() else {}
        for path in sorted(Path(extra).glob("*.pcap")):
            options = overrides.get(path.name, {})
            flow_type = options.get("flow_type", "sflow" if "sflow" in path.name.lower() else "netflow")
            port = options.get("port")
            decode_as = f"udp.port=={port},{'sflow' if flow_type == 'sflow' else 'cflow'}" if port else None
            cases.append(pytest.param(path, flow_type, options.get("limit", ORACLE_LIMIT), decode_as, id=path.name))
    return cases


@pytest.fixture(scope="session")
def tshark() -> Path:
    path = oracle.find_tshark()
    if path is None:
        pytest.skip("tshark not found; set TSHARK or install Wireshark")
    return path


@pytest.mark.parametrize("pcap,flow_type,limit,decode_as", captures())
def test_structure_matches_wireshark(tshark, rustflow_bin, pcap, flow_type, limit, decode_as):
    protocol = "sflow" if flow_type == "sflow" else "cflow"
    theirs = oracle.tshark_layers(tshark, pcap, protocol, limit, decode_as)
    ours = oracle.rustflow_raw(rustflow_bin, pcap, flow_type, limit)

    if flow_type == "sflow":
        expected = [oracle.sflow_summary(layer) for layer in theirs]
        actual = [oracle.rustflow_sflow_summary(raw) for raw in ours]
    else:
        expected = [oracle.v5_summary(l) if oracle.num(l["cflow.version"]) == 5 else oracle.cflow_summary(l) for l in theirs]
        actual = [oracle.rustflow_v5_summary(r) if r["version"] == 5 else oracle.rustflow_cflow_summary(r) for r in ours]

    difference = oracle.first_difference(expected, actual)
    assert difference is None, difference


@pytest.mark.parametrize("pcap,flow_type,limit,decode_as", [c for c in captures() if c.values[1] == "netflow"])
def test_record_values_match_wireshark(tshark, rustflow_bin, pcap, flow_type, limit, decode_as):
    theirs = oracle.tshark_layers(tshark, pcap, "cflow", limit, decode_as)
    ours = oracle.rustflow_raw(rustflow_bin, pcap, flow_type, limit)
    mismatches, compared, decoded = oracle.compare_values(theirs, ours)
    assert not mismatches, f"{len(mismatches)} mismatches after {compared} fields compared:\n" + "\n".join(mismatches)
    # Nothing to compare when tshark decoded no records either: NetFlow v5
    # has no templates (its records are level 1), and a capture may hold
    # data whose templates never arrive.
    if decoded:
        assert compared > 0, "tshark decoded records but none were compared"


@pytest.mark.parametrize("pcap,flow_type,limit,decode_as", [c for c in captures() if c.values[1] == "sflow"])
def test_sampled_headers_match_wireshark(tshark, rustflow_bin, pcap, flow_type, limit, decode_as):
    theirs = oracle.tshark_layers(tshark, pcap, "sflow", limit, decode_as)
    ours = oracle.rustflow_common(rustflow_bin, pcap, flow_type, limit)
    mismatches, compared = oracle.compare_sflow(theirs, ours)
    assert not mismatches, f"{len(mismatches)} mismatches after {compared} fields compared:\n" + "\n".join(mismatches)
    assert compared > 0, "no flow samples were compared"
