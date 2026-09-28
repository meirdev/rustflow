"""Wireshark as an oracle: reduce a `tshark -T json` decode and a `rustflow
collect --format raw` replay of the same capture to one structural summary
per packet, so they can be compared.

Level 1 covers what needs no field-name mapping: message headers, the sets
in each message with their ids and lengths, every template with its ordered
field types, lengths and enterprise numbers, how many records each data set
decoded to, and which data sets had no template. For NetFlow v5 the format
is fixed, so its records are compared as well. For sFlow it covers every
sample's header fields and the format and length of every record.
"""

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TSHARK_CANDIDATES = [
    os.environ.get("TSHARK"),
    shutil.which("tshark"),
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
]


def find_tshark() -> Path | None:
    for candidate in TSHARK_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def tshark_layers(tshark: Path, pcap: Path, protocol: str, limit: int | None = None, decode_as: str | None = None) -> list[dict]:
    """The `protocol` layer of each packet, as tshark's JSON tree."""
    cmd = [str(tshark), "-r", str(pcap), "-T", "json", "-J", protocol]
    if limit:
        cmd += ["-c", str(limit)]
    if decode_as:
        cmd += ["-d", decode_as]
    # Absolute times are rendered in the local zone; pin it so they parse.
    env = {**os.environ, "TZ": "UTC"}
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env).stdout
    packets = json.loads(out, object_pairs_hook=keep_duplicates) if out.strip() else []
    return [p["_source"]["layers"].get(protocol, {}) for p in packets]


def keep_duplicates(pairs: list) -> dict:
    """tshark repeats a key for repeated subtrees, such as five counter
    samples with the same sequence number; a plain dict would keep only
    the last. Repeats get a ` #n` suffix so document order survives."""
    tree: dict = {}
    for key, value in pairs:
        unique, n = key, 1
        while unique in tree:
            n += 1
            unique = f"{key} #{n}"
        tree[unique] = value
    return tree


def find_editcap() -> Path | None:
    """editcap ships next to tshark."""
    tshark = find_tshark()
    for candidate in [shutil.which("editcap"), tshark.with_name("editcap") if tshark else None]:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def rustflow_raw(rustflow: Path, pcap: Path, flow_type: str, limit: int | None = None) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        editcap = find_editcap() if limit else None
        if editcap:
            # Replaying a large capture whole only to keep its head is slow.
            head = Path(tmp) / pcap.name
            subprocess.run([str(editcap), "-F", "pcap", "-r", str(pcap), str(head), f"1-{limit}"], capture_output=True, check=True)
            pcap = head
        cmd = [str(rustflow), "collect", "-t", flow_type, "--pcap", str(pcap), "--format", "raw", "--serialization", "ndjson"]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    # A template may carry an element twice (ingress and egress interfaceName), and the raw map then repeats the key.
    packets = [json.loads(line, object_pairs_hook=keep_duplicates) for line in out.splitlines() if line.strip()]
    return packets[:limit] if limit else packets


# --------------------------------------------------------------- helpers

def num(v):
    """tshark renders every number as a string, sometimes in hex."""
    if isinstance(v, str):
        return int(v, 0)
    return v


def epoch(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def subtrees(tree: dict, prefix: str) -> list[dict]:
    """Child dicts whose key starts with `prefix`, in document order."""
    return [v for k, v in tree.items() if k.startswith(prefix) and isinstance(v, dict)]


# ------------------------------------------------- NetFlow v9 and IPFIX

V9_SCOPE_TYPES = {"System": 1, "Interface": 2, "LineCard": 3, "Cache": 4, "Template": 5}


def cflow_template_fields(tree: dict) -> tuple[list, list]:
    """(scope fields, fields) of a tshark template subtree, each a list of
    [type, length, enterprise number]."""
    scope, fields = [], []
    for key, field in tree.items():
        if not (key.startswith("Field ") and isinstance(field, dict)):
            continue
        length = num(field["cflow.template_field_length"])
        if "cflow.scope_field_type" in field:
            scope.append([num(field["cflow.scope_field_type"]), length, None])
            continue
        # The type key is per vendor: `cflow.template_ipfix_field_type`,
        # `cflow.template_ipfix_field_type_enterprise` for an unknown
        # enterprise, `cflow.template_ixia_field_type` or
        # `cflow.template_juniper_resiliency_type` for a known one, ...
        ftype = num(next(v for k, v in field.items() if "_type" in k))
        pen = num(field["cflow.template_ipfix_field_pen"]) if num(field.get("cflow.template_ipfix_pen_provided", 0)) else None
        (scope if "[Scope]" in key else fields).append([ftype, length, pen])
    return scope, fields


def cflow_summary(layer: dict) -> dict:
    version = num(layer["cflow.version"])
    if version == 10:
        packet = {
            "version": 10,
            "length": num(layer["cflow.len"]),
            "export_time": num(layer["cflow.timestamp_tree"]["cflow.exporttime"]),
            "sequence": num(layer["cflow.sequence"]),
            "domain": num(layer["cflow.od_id"]),
        }
    else:
        packet = {
            "version": version,
            "count": num(layer["cflow.count"]),
            "uptime_ms": round(float(layer["cflow.sysuptime"]) * 1000),
            "unix_secs": num(layer["cflow.timestamp_tree"]["cflow.unix_secs"]),
            "sequence": num(layer["cflow.sequence"]),
            "domain": num(layer["cflow.source_id"]),
        }
    sets = []
    for tree in subtrees(layer, "FlowSet ") + subtrees(layer, "Set "):
        entry = {"id": num(tree["cflow.flowset_id"]), "length": num(tree["cflow.flowset_length"])}
        templates = subtrees(tree, "Template (") + subtrees(tree, "Options Template (")
        if templates:
            entry["templates"] = []
            for t in templates:
                scope, fields = cflow_template_fields(t)
                entry["templates"].append({"id": num(t["cflow.template_id"]), "scope": scope, "fields": fields})
        elif any(k.startswith("Data (") and "no template found" in k for k in tree):
            entry["records"] = None
        else:
            entry["records"] = len(subtrees(tree, "Flow "))
        sets.append(entry)
    packet["sets"] = sets
    return packet


def rustflow_cflow_summary(raw: dict) -> dict:
    if raw["version"] == 10:
        packet = {
            "version": 10,
            "length": raw["length"],
            "export_time": epoch(raw["export_time"]),
            "sequence": raw["sequence_number"],
            "domain": raw["observation_domain_id"],
        }
        sets = raw["sets"]
    else:
        packet = {
            "version": raw["version"],
            "count": raw["count"],
            "uptime_ms": raw["system_uptime"],
            "unix_secs": epoch(raw["unix_seconds"]),
            "sequence": raw["sequence_number"],
            "domain": raw["source_id"],
        }
        sets = raw["flow_sets"]
    summary = []
    for s in sets:
        entry = {"id": s["id"], "length": s["length"]}
        records = s["records"]
        if records and "fields" in records[0]:
            entry["templates"] = [rustflow_template(r) for r in records]
        elif records and "option_fields" in records[0]:
            entry["templates"] = [rustflow_template(r) for r in records]
        elif not records and s["length"] > 4 and s["id"] >= 256:
            entry["records"] = None
        else:
            entry["records"] = len(records)
        summary.append(entry)
    packet["sets"] = summary
    return packet


def rustflow_template(record: dict) -> dict:
    if "information_element_identifier" in (record.get("fields") or [{}])[0]:
        # IPFIX: scope fields are the first `scope_field_count` fields
        fields = [[f["information_element_identifier"], f["field_length"], f["enterprise_number"]] for f in record["fields"]]
        n = record.get("scope_field_count", 0)
        return {"id": record["template_id"], "scope": fields[:n], "fields": fields[n:]}
    if "scope_fields" in record:
        scope = []
        for f in record["scope_fields"]:
            t = f["type"]
            scope.append([V9_SCOPE_TYPES[t] if isinstance(t, str) else t["Unknown"], f["length"], None])
        return {"id": record["id"], "scope": scope, "fields": [[f["type"], f["length"], None] for f in record["option_fields"]]}
    return {"id": record["id"], "scope": [], "fields": [[f["type"], f["length"], None] for f in record["fields"]]}


# ------------------------------------------------------------ NetFlow v5

V5_PDU_FIELDS = {
    # tshark name: rustflow name
    "srcaddr": "srcaddr", "dstaddr": "dstaddr", "nexthop": "nexthop",
    "inputint": "input", "outputint": "output", "packets": "d_pkts", "octets": "d_ockts",
    "srcport": "srcport", "dstport": "dstport", "tcpflags": "tcp_flags", "protocol": "prot",
    "tos": "tos", "srcas": "src_as", "dstas": "dst_as", "srcmask": "src_mask", "dstmask": "dst_mask",
}


def v5_summary(layer: dict) -> dict:
    ts = layer["cflow.timestamp_tree"]
    packet = {
        "version": 5,
        "count": num(layer["cflow.count"]),
        "uptime_ms": round(float(layer["cflow.sysuptime"]) * 1000),
        "unix_secs": num(ts["cflow.unix_secs"]),
        "unix_nsecs": num(ts["cflow.unix_nsecs"]),
        "sequence": num(layer["cflow.sequence"]),
        "engine_type": num(layer["cflow.engine_type"]),
        "engine_id": num(layer["cflow.engine_id"]),
        "sampling_mode": num(layer["cflow.samplingmode"]),
        "sampling_interval": num(layer["cflow.samplerate"]),
    }
    packet["records"] = [
        {ours: (num(pdu[f"cflow.{theirs}"]) if theirs not in ("srcaddr", "dstaddr", "nexthop") else pdu[f"cflow.{theirs}"])
         for theirs, ours in V5_PDU_FIELDS.items()}
        for pdu in subtrees(layer, "pdu ")
    ]
    return packet


def rustflow_v5_summary(raw: dict) -> dict:
    uptime = datetime.fromisoformat(raw["sys_uptime"].replace("Z", "+00:00"))
    packet = {
        "version": 5,
        "count": raw["count"],
        "uptime_ms": round((uptime - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1000),
        "unix_secs": raw["unix_secs"],
        "unix_nsecs": raw["unix_nsecs"],
        "sequence": raw["flow_sequence"],
        "engine_type": raw["engine_type"],
        "engine_id": raw["engine_id"],
        "sampling_mode": raw["sampling_mode"],
        "sampling_interval": raw["sampling_interval"],
    }
    packet["records"] = [{ours: r[ours] for ours in V5_PDU_FIELDS.values()} for r in raw["flow_records"]]
    return packet


# ------------------------------------------------------------------ sFlow

SFLOW_SAMPLE_PREFIXES = ("Flow sample", "Counters sample", "Expanded flow sample", "Expanded counters sample", "Discarded packet")


def sflow_summary(layer: dict) -> dict:
    packet = {
        "agent": layer["sflow_245.agent"],
        "sub_agent": num(layer["sflow_245.sub_agent_id"]),
        "sequence": num(layer["sflow_245.sequence_number"]),
        "uptime": num(layer["sflow_245.sysuptime"]),
        "samples": [],
    }
    for key, tree in layer.items():
        if not (isinstance(tree, dict) and key.startswith(SFLOW_SAMPLE_PREFIXES)):
            continue
        sample = {"type": num(tree["sflow_245.sampletype"]), "length": num(tree["sflow_5.sample_length"])}
        flow = {k[len("sflow.flow_sample."):]: v for k, v in tree.items() if k.startswith("sflow.flow_sample.") and not isinstance(v, dict)}
        counters = {k[len("sflow.counters_sample."):]: v for k, v in tree.items() if k.startswith("sflow.counters_sample.")}
        if flow:
            sample.update(
                sequence=num(flow["sequence_number"]),
                source_type=num(flow.get("source_id_class", flow.get("source_id_type", 0))),
                source_index=num(flow.get("index", flow.get("source_id_index", 0))),
                sampling_rate=num(flow["sampling_rate"]),
                pool=num(flow["sample_pool"]),
                drops=num(flow["dropped_packets"]),
                input=num(flow["input_interface"]),
                output=num(flow["output_interface"]),
            )
            sample["records"] = [
                [num(r["sflow_245.flow_record_format"]), num(r["sflow_5.flow_data_length"])]
                for r in tree.values() if isinstance(r, dict) and "sflow_245.flow_record_format" in r
            ]
        elif counters:
            sample.update(
                sequence=num(counters["sequence_number"]),
                source_type=num(counters["source_id_type"]),
                source_index=num(counters["source_id_index"]),
            )
            sample["records"] = [
                [num(r["sflow_245.counters_record_format"]), num(r["sflow_5.flow_data_length"])]
                for r in tree.values() if isinstance(r, dict) and "sflow_245.counters_record_format" in r
            ]
        packet["samples"].append(sample)
    return packet


def rustflow_sflow_summary(raw: dict) -> dict:
    packet = {
        "agent": raw["agent_address"],
        "sub_agent": raw["sub_agent_id"],
        "sequence": raw["sequence_number"],
        "uptime": raw["uptime"],
        "samples": [],
    }
    for wrapped in raw["samples"]:
        kind, s = next(iter(wrapped.items()))
        if kind == "Unknown":
            packet["samples"].append({"type": None})
            continue
        h = s["header"]
        sample = {"type": h["format"], "length": h["length"], "sequence": h["sample_sequence_number"],
                  "source_type": h["source_id_type"], "source_index": h["source_id_value"]}
        if kind in ("Flow", "ExpandedFlow"):
            sample.update(
                sampling_rate=s["sampling_rate"], pool=s["sample_pool"], drops=s["drops"],
                input=s.get("input", s.get("input_if_value")), output=s.get("output", s.get("output_if_value")),
            )
        sample["records"] = [[r["header"]["data_format"], r["header"]["length"]] for r in s["records"]]
        packet["samples"].append(sample)
    return packet


# ------------------------------------------------------------- comparing

def first_difference(expected: list, actual: list) -> str | None:
    """A readable description of the first packet whose summaries differ:
    the path to the first differing value, then both packets in full."""
    if len(expected) != len(actual):
        return f"packet count: tshark {len(expected)}, rustflow {len(actual)}"
    for i, (e, a) in enumerate(zip(expected, actual)):
        if e != a:
            return (f"packet {i + 1} differs at {path_difference(e, a)}\n"
                    f"--- tshark\n{json.dumps(e, indent=1)}\n--- rustflow\n{json.dumps(a, indent=1)}")
    return None


def path_difference(a, b, path: str = "") -> str:
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                return f"{path}.{key}: only rustflow has it ({json.dumps(b[key])[:120]})"
            if key not in b:
                return f"{path}.{key}: only tshark has it ({json.dumps(a[key])[:120]})"
            if a[key] != b[key]:
                return path_difference(a[key], b[key], f"{path}.{key}")
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path}: tshark has {len(a)} items, rustflow {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return path_difference(x, y, f"{path}[{i}]")
    return f"{path}: tshark {a!r}, rustflow {b!r}"


# ------------------------------------------- level 2: data record values
#
# tshark lists a record's fields in template order, so the two sides can be
# zipped positionally; what differs is only how each value is rendered.

TIME_STARTS = ("cflow.abstimestart", "cflow.timestart")
TIME_PAIRS = ("cflow.abstimestart", "cflow.abstimeend", "cflow.timestart", "cflow.timeend")
VENDOR_SECTION = re.compile(r"cflow\.pie\.[a-z0-9_]+$")
MAC_OR_BYTES = re.compile(r"^([0-9a-f]{2}:)+[0-9a-f]{2}$")
STRUCTURED = "<structured>"
TSHARK_TIME = re.compile(r"^[A-Z][a-z]{2} +\d{1,2}, \d{4} \d\d:\d\d:\d\d\.\d+ UTC$")


def tshark_record_values(flow: dict) -> list[tuple[str, object]]:
    """A record's (key, rendered value) pairs in template order. A time
    pair is one `timedelta` leaf plus a tree with the two times, so the
    tree is expanded and the leaf dropped; other trees are decoration."""
    values = []
    for key, value in flow.items():
        key = key.split(" #")[0]  # the suffix keep_duplicates added
        if key.startswith("_ws") or key == "cflow.padding" or key == "cflow.timedelta":
            continue
        # icmpTypeCodeIPv6 is one 16-bit element that tshark shows as two.
        if key == "cflow.icmp_ipv6_code" and values and values[-1][0] == "cflow.icmp_ipv6_type":
            values[-1] = ("cflow.icmp_ipv6_type_code", (num(values[-1][1]) << 8) | num(value))
            continue
        # applicationId is one octet array: an engine id byte and a selector.
        if key == "cflow.appl_id.selector_id" and values and values[-1][0] == "cflow.appl_id.classification_engine_id":
            values[-1] = ("cflow.appl_id", f"{num(values[-1][1]):02x}:{value}")
            continue
        if key.endswith("_tree"):
            if isinstance(value, dict):
                values.extend((k, value[k]) for k in TIME_PAIRS if k in value)
            continue
        # forwardingStatus: two status bits, then a reason code whose leaf
        # is named after the status (forward_code, drop_code, ...)
        if key == "Forwarding Status":
            reason = next((num(v) for k, v in value.items() if k != "cflow.forwarding_status"), 0)
            values.append(("cflow.forwarding_status", (num(value["cflow.forwarding_status"]) << 6) | reason))
            continue
        if VENDOR_SECTION.match(key):
            continue
        values.append((key, STRUCTURED if isinstance(value, (dict, list)) else value))
    return values


def rustflow_record_values(record: dict) -> list[tuple[str, object]]:
    """(name, value) pairs. A zero-length field is null, or an empty string
    or octet array, and tshark shows nothing for it."""
    return [(name.split(" #")[0], STRUCTURED if isinstance(v, (dict, list)) else v)
            for name, v in record.items() if v is not None and v != ""]


def parse_tshark_time_ns(text: str) -> int:
    """`Jan 25, 2026 12:44:48.664000000 UTC` to nanoseconds since the epoch."""
    stamp, fraction = text.rsplit(" ", 1)[0].split(".")
    base = datetime.strptime(stamp, "%b %d, %Y %H:%M:%S").replace(tzinfo=timezone.utc)
    return int(base.timestamp()) * 1_000_000_000 + int(fraction.ljust(9, "0")[:9])


def parse_iso_ns(text: str) -> int:
    stamp, _, fraction = text.rstrip("Z").partition(".")
    base = datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc)
    return int(base.timestamp()) * 1_000_000_000 + int((fraction or "0").ljust(9, "0")[:9])


def is_hex(value) -> bool:
    return isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", value) is not None


def values_match(theirs_key: str, theirs, ours_name: str, ours, export_time: int | None) -> bool:
    if theirs == STRUCTURED or ours == STRUCTURED:
        # A vendor structure tshark knows how to decode is raw hex on our
        # side; there is nothing to compare it against.
        return theirs == ours or (theirs == STRUCTURED and is_hex(ours))
    theirs = str(theirs)

    # Times: tshark makes every timestamp absolute and renders it.
    if theirs_key in ("cflow.abstimestart", "cflow.abstimeend") or TSHARK_TIME.match(theirs):
        want = parse_tshark_time_ns(theirs)
        if isinstance(ours, str):
            return parse_iso_ns(ours) == want
        if "DeltaMicroseconds" in ours_name and export_time is not None:
            return export_time * 1_000_000_000 - int(ours) * 1_000 == want
        return False
    if theirs_key in ("cflow.timestart", "cflow.timeend"):
        # v9 sysuptime-relative, seconds on their side and milliseconds on ours
        return round(float(theirs) * 1000) == int(ours)
    if theirs_key == "cflow.forwarding_status":
        # one byte, or the low byte of the unsigned32 form
        return isinstance(ours, int) and ours & 0xFF == int(theirs)

    # Our value is raw hex when the element is unknown to our registry.
    if is_hex(ours) and not theirs.startswith("0x"):
        raw = bytes.fromhex(ours)
        if MAC_OR_BYTES.match(theirs):
            return theirs.replace(":", "") == ours
        if len(raw) == 4 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", theirs):
            return socket.inet_aton(theirs) == raw
        if len(raw) == 16 and ":" in theirs:
            return socket.inet_pton(socket.AF_INET6, theirs) == raw
        if re.fullmatch(r"-?\d+", theirs) and len(raw) <= 8:
            return int.from_bytes(raw, "big") == int(theirs) or ours == theirs
        if re.fullmatch(r"-?\d+\.\d+", theirs) and len(raw) in (4, 8):
            value = struct.unpack(">f" if len(raw) == 4 else ">d", raw)[0]
            return abs(value - float(theirs)) <= 1e-4 * max(1.0, abs(value))
        text = raw.decode("utf-8", "replace").rstrip("\x00")
        return text == theirs or text.strip() == theirs.strip() or ours == theirs

    if isinstance(ours, bool):
        return theirs in ("1", "True", "true") if ours else theirs in ("0", "False", "false")
    if isinstance(ours, int):
        try:
            return int(theirs, 0) == ours
        except ValueError:
            return False
    if isinstance(ours, float):
        try:
            return abs(float(theirs) - ours) <= 1e-4 * max(1.0, abs(ours))
        except ValueError:
            return False
    if MAC_OR_BYTES.match(theirs):
        return theirs.lower() == str(ours).lower()
    return theirs == str(ours) or theirs.strip() == str(ours).strip()


def compare_values(theirs: list[dict], ours: list[dict], limit: int = 20) -> tuple[list[str], int, int]:
    """Mismatches between every data record of every packet, as readable
    lines, plus the number of fields compared and of records tshark decoded."""
    mismatches, compared, decoded = [], 0, 0
    for i, (layer, raw) in enumerate(zip(theirs, ours)):
        if num(layer["cflow.version"]) not in (9, 10):
            continue
        export_time = epoch(raw["export_time"]) if raw["version"] == 10 else None
        their_sets = subtrees(layer, "FlowSet ") + subtrees(layer, "Set ")
        our_sets = raw.get("sets", raw.get("flow_sets"))
        for set_index, (their_set, our_set) in enumerate(zip(their_sets, our_sets)):
            flows = subtrees(their_set, "Flow ")
            records = [r for r in our_set["records"] if "fields" not in r and "option_fields" not in r]
            decoded += len(flows)
            if not flows or not records:
                continue
            where = f"packet {i + 1} set {our_set['id']}"
            for r, (flow, record) in enumerate(zip(flows, records)):
                a, b = tshark_record_values(flow), rustflow_record_values(record)
                # tshark lists a time pair start first whatever the template order
                for k in range(min(len(a), len(b)) - 1):
                    if a[k][0] in TIME_STARTS and "End" in b[k][0] and "Start" in b[k + 1][0]:
                        a[k], a[k + 1] = a[k + 1], a[k]
                if len(a) != len(b):
                    mismatches.append(f"{where} record {r + 1}: tshark has {len(a)} fields, rustflow {len(b)}\n"
                                      f"    tshark:   {[k for k, _ in a]}\n    rustflow: {[k for k, _ in b]}")
                else:
                    for n, ((tk, tv), (on, ov)) in enumerate(zip(a, b)):
                        compared += 1
                        if not values_match(tk, tv, on, ov, export_time):
                            mismatches.append(f"{where} record {r + 1} field {n + 1}: {tk}={tv!r} vs {on}={ov!r}")
                if len(mismatches) >= limit:
                    return mismatches, compared, decoded
    return mismatches, compared, decoded


# ------------------------------------------------ level 2, sFlow

# Tunnels we peel in a sampled header: the frame or packet after one of
# these replaces the outer network and transport headers.
TUNNEL_LAYERS = {"gre", "vxlan", "geneve"}


def rustflow_common(rustflow: Path, pcap: Path, flow_type: str, limit: int | None = None) -> list[dict]:
    """Common flows, one per flow sample in packet order."""
    with tempfile.TemporaryDirectory() as tmp:
        editcap = find_editcap() if limit else None
        if editcap:
            head = Path(tmp) / pcap.name
            subprocess.run([str(editcap), "-F", "pcap", "-r", str(pcap), str(head), f"1-{limit}"], capture_output=True, check=True)
            pcap = head
        cmd = [str(rustflow), "collect", "-t", flow_type, "--pcap", str(pcap), "--format", "common", "--serialization", "ndjson"]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        return [json.loads(line) for line in out.splitlines() if line.strip()]


def sflow_header_fields(tree: dict) -> dict:
    """Common-flow fields from tshark's dissection of a sampled header:
    the Ethernet header and VLAN tag of the innermost frame, and the
    innermost IP and transport headers, reachable through the tunnels we
    peel. Any other layer ends the walk, so an unpeeled encapsulation
    keeps its outer headers."""
    fields, net, transport = {}, {}, {}
    after_tunnel = False
    for key, layer in tree.items():
        name = key.split(" #")[0]
        if not isinstance(layer, dict):
            continue
        if name == "eth":
            # A frame inside a tunnel is the packet; its link replaces the outer one.
            if "src_mac" not in fields or after_tunnel:
                fields = dict(src_mac=layer["eth.src"], dst_mac=layer["eth.dst"], etype=num(layer["eth.type"]))
        elif name == "vlan":
            if "vlan_id" not in fields:
                fields.update(vlan_id=num(layer["vlan.id"]), etype=num(layer["vlan.etype"]))
        elif name in ("ip", "ipv6"):
            if net and not after_tunnel:
                break
            after_tunnel = False
            transport = {}
            if name == "ip":
                net = dict(src_addr=layer["ip.src"], dst_addr=layer["ip.dst"], proto=num(layer["ip.proto"]), ip_ttl=num(layer["ip.ttl"]),
                           ip_tos=num(layer["ip.dsfield"]), fragment_id=num(layer["ip.id"]), fragment_offset=num(layer["ip.frag_offset"]))
            else:
                net = dict(src_addr=layer["ipv6.src"], dst_addr=layer["ipv6.dst"], proto=num(layer["ipv6.nxt"]), ip_ttl=num(layer["ipv6.hlim"]),
                           ip_tos=num(layer["ipv6.tclass"]), ipv6_flow_label=num(layer["ipv6.flow"]))
        elif name in ("tcp", "udp"):
            transport = dict(src_port=num(layer[f"{name}.srcport"]), dst_port=num(layer[f"{name}.dstport"]))
            if name == "tcp":
                transport["tcp_flags"] = num(layer["tcp.flags"])
        elif name in ("icmp", "icmpv6"):
            transport = dict(icmp_type=num(layer[f"{name}.type"]), icmp_code=num(layer[f"{name}.code"]))
        elif name in TUNNEL_LAYERS:
            after_tunnel = True
        else:
            break
    return {**fields, **net, **transport}


def vlan_or_none(value) -> int | None:
    return num(value) if num(value) <= 0xFFFF else None


def sflow_expected(layer: dict) -> list[dict]:
    """The common flow tshark implies for each flow sample of a datagram."""
    flows = []
    for key, tree in layer.items():
        if not (isinstance(tree, dict) and key.startswith(SFLOW_SAMPLE_PREFIXES)) or "sflow.flow_sample.sequence_number" not in tree:
            continue
        flow = {
            "sampler_address": layer.get("sflow_245.agent", layer.get("sflow_245.agent.v6")),
            "sequence_num": num(layer["sflow_245.sequence_number"]),
            "sampling_rate": num(tree["sflow.flow_sample.sampling_rate"]),
            "in_if": num(tree["sflow.flow_sample.input_interface"]),
            "out_if": num(tree["sflow.flow_sample.output_interface"]),
        }
        header = {}
        for record in tree.values():
            if not isinstance(record, dict) or "sflow_245.flow_record_format" not in record:
                continue
            match num(record["sflow_245.flow_record_format"]):
                case 1:
                    flow["bytes"] = num(record["sflow_245.header.frame_length"])
                    flow["packets"] = 1
                    header = sflow_header_fields(record.get("sflow_245.header_tree", {}))
                case 1001:
                    # 0xFFFFFFFF is "unknown", which we leave unset
                    flow["src_vlan"] = vlan_or_none(record["sflow_245.vlan.in"])
                    flow["dst_vlan"] = vlan_or_none(record["sflow_245.vlan.out"])
                case 1002:
                    flow["next_hop"] = record.get("sflow_245.nexthop.v6", record.get("sflow_245.nexthop"))
                    flow["src_net"] = num(record["sflow_245.nexthop.src_mask"])
                    flow["dst_net"] = num(record["sflow_245.nexthop.dst_mask"])
        # The frame's VLAN tag only when no extended switch record says better.
        vlan_id = header.pop("vlan_id", None)
        if vlan_id is not None and "src_vlan" not in flow:
            flow["src_vlan"] = vlan_id
        flows.append({**header, **flow})
    return flows


def sflow_values_match(name: str, theirs, ours) -> bool:
    if isinstance(theirs, str) and isinstance(ours, str):
        return theirs.lower() == ours.lower()
    return theirs == ours


def compare_sflow(theirs: list[dict], ours: list[dict], limit: int = 20) -> tuple[list[str], int]:
    """Mismatches between the flow tshark implies for every flow sample
    and the common flow we produce for it, plus the number of fields
    compared. Only fields tshark has are compared."""
    expected = [(i, j, flow) for i, layer in enumerate(theirs) for j, flow in enumerate(sflow_expected(layer))]
    if len(expected) != len(ours):
        return [f"tshark has {len(expected)} flow samples, rustflow {len(ours)} common flows"], 0
    mismatches, compared = [], 0
    for (packet, sample, want), got in zip(expected, ours):
        for name, value in want.items():
            compared += 1
            if not sflow_values_match(name, value, got.get(name)):
                mismatches.append(f"packet {packet + 1} sample {sample + 1}: {name} tshark={value!r} rustflow={got.get(name)!r}")
                if len(mismatches) >= limit:
                    return mismatches, compared
    return mismatches, compared
