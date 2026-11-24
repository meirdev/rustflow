"""The common flows a collector makes of the packets a case expects.

A model of the conversion to the common flow (docs/output.md), written
apart from rustflow's: it reads the packets as a case writes them, in the
shape of `--format raw`, and gives the flows `--format common` must print.
Where the two disagree, either rustflow or this model is wrong.

The model follows these rules:

- NetFlow v9 and IPFIX: each data record is a flow; the elements map to
  the flow's fields by their IANA name, a later element overwriting an
  earlier one except where it only fills a gap (octetTotalCount after
  octetDeltaCount, minimumTTL after ipTTL). Times relative to the
  exporter's uptime need the packet's (v9) or the domain's
  systemInitTimeMilliseconds (IPFIX); 32-bit second counters take the era
  nearest the packet's export time (RFC 7011 section 5.2).
- Sampling: a rate in the record itself; else from options records, by
  the sampler the record names, in its domain and then any domain of the
  exporter; then the domain's own rate; then the rate every sampler of the
  domain agrees on; then the latest rate of a NetFlow v9 System-scoped
  record, which covers the whole exporter. A record scoped to an interface
  or a line card gives only a rate that names a sampler.
- sFlow: each flow sample is one sampled packet; the sampled header is
  read down to the transport header, and the other records fill in or
  overwrite what it gave.

Tunnels inside a sampled header are not modeled; a case that needs them
stops the generator.
"""

import ipaddress
import re
from datetime import datetime, timezone

NS = 1_000_000_000
MS = 1_000_000
ERA = 1 << 32
NTP_EPOCH = -2_208_988_800  # 1900-01-01 in Unix seconds

ETHER_IPV4, ETHER_IPV6 = 0x0800, 0x86DD
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def common_flows(packets: list[tuple[int, str, dict]]) -> list[dict]:
    """The flows of the packets a case expects, each with the Unix second
    it was received at and the address it came from."""
    exporters: dict[str, Exporter] = {}
    out = []
    for received, sender, text in packets:
        protocol, packet = text["protocol"], text["packet"]
        base = {"flow_type": protocol.upper(), "time_received_ns": received * NS}
        sender = str(ipaddress.ip_address(sender))
        if protocol == "netflow_v5":
            out += netflow_v5(base, sender, packet)
        elif protocol == "sflow_v5":
            out += sflow_v5(base, packet)
        else:
            out += templated(base, sender, protocol, packet, exporters.setdefault(sender, Exporter()))
    return [{key: value for key, value in flow.items() if value is not None} for flow in out]


# Values as `--format raw` prints them.


def number(value) -> int | None:
    """An unsigned integer; booleans, floats, text and lists are not."""
    return value if type(value) is int and value >= 0 else None


def narrow(value, bits: int) -> int | None:
    n = number(value)
    return n if n is not None and n < 1 << bits else None


def address(value) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def mac(value) -> str | None:
    return value if isinstance(value, str) and MAC.match(value) else None


def instant(text: str) -> tuple[int, int]:
    """An RFC 3339 time as Unix seconds and nanoseconds."""
    whole, _, fraction = text.rstrip("Z").partition(".")
    seconds = int(datetime.fromisoformat(whole).replace(tzinfo=timezone.utc).timestamp())
    return seconds, int(fraction.ljust(9, "0")) if fraction else 0


def nearest_era(seconds: int, epoch: int, reference: int) -> int:
    """A 32-bit seconds counter starting at `epoch`, in the era nearest
    `reference`."""
    era = (reference - epoch - seconds + ERA // 2) // ERA
    return epoch + era * ERA + seconds


def is_time(value) -> bool:
    """A time, rather than the octets of a field too short for one."""
    return isinstance(value, str) and value.endswith("Z")


def timestamp_ns(name: str, value, export_secs: int) -> int | None:
    if not is_time(value):
        return None
    seconds, nanos = instant(value)
    if name.endswith("Seconds"):
        seconds = nearest_era(seconds % ERA, 0, export_secs)
    elif name.endswith(("Microseconds", "Nanoseconds")):
        seconds = nearest_era((seconds - NTP_EPOCH) % ERA, NTP_EPOCH, export_secs)
    return seconds * NS + nanos


# NetFlow v5.


def netflow_v5(base: dict, sender: str, packet: dict) -> list[dict]:
    export_ns = packet["unix_secs"] * NS + packet["unix_nsecs"]

    def uptime_ns(uptime: int) -> int:
        return export_ns - ((packet["sys_uptime"] - uptime) % ERA) * MS

    rate = packet["sampling_interval"]["interval"]
    out = []
    for r in packet["flow_records"]:
        # ICMP carries its type and code in the destination port.
        icmp = r["prot"] == 1
        out.append(
            base
            | {
                "sampler_address": sender,
                "sequence_num": packet["flow_sequence"],
                "sampling_rate": rate or None,
                "time_flow_start_ns": uptime_ns(r["first"]),
                "time_flow_end_ns": uptime_ns(r["last"]),
                "bytes": r["d_octets"],
                "packets": r["d_pkts"],
                "src_addr": r["srcaddr"],
                "dst_addr": r["dstaddr"],
                "etype": ETHER_IPV4,
                "proto": r["prot"],
                "src_port": None if icmp else r["srcport"],
                "dst_port": None if icmp else r["dstport"],
                "icmp_type": r["dstport"] >> 8 if icmp else None,
                "icmp_code": r["dstport"] & 0xFF if icmp else None,
                "in_if": r["input"],
                "out_if": r["output"],
                "ip_tos": r["tos"],
                "tcp_flags": r["tcp_flags"],
                "src_as": r["src_as"],
                "dst_as": r["dst_as"],
                "next_hop": r["nexthop"],
                "src_net": r["src_mask"],
                "dst_net": r["dst_mask"],
            }
        )
    return out


# NetFlow v9 and IPFIX.

# Scope fields that cover part of a domain: v9 scope types by the name
# they print as (an unknown one prints as its number, and may be any part),
# IPFIX elements by ID.
V9_PARTIAL = {"Interface", "LineCard", "Template"}
IPFIX_PARTIAL = {10, 14, 141, 145}


def extent(v9: bool, scopes: list[dict]) -> str:
    if v9:
        types = [s["field_type"] for s in scopes]
        if any(not isinstance(t, str) or t in V9_PARTIAL for t in types):
            return "partial"
        return "system" if "System" in types else "domain"
    partial = any(s.get("enterprise_number") is None and s["information_element_id"] in IPFIX_PARTIAL for s in scopes)
    return "partial" if partial else "domain"


class Sampling:
    """The sampling elements of one record."""

    def __init__(self, record: dict):
        self.rate = self.packet_interval = self.packet_space = None
        self.size = self.population = self.sampler = None
        for name, value in elements(record):
            n = narrow(value, 32)
            if name in ("samplingInterval", "samplerRandomInterval"):
                self.rate = n
            elif name == "samplingPacketInterval":
                self.packet_interval = n
            elif name == "samplingPacketSpace":
                self.packet_space = n
            elif name == "samplingSize":
                self.size = n
            elif name == "samplingPopulation":
                self.population = n
            elif name in ("samplerId", "selectorId"):
                self.sampler = number(value)

    def one_in(self) -> int | None:
        """The 1-in-N rate (PSAMP pairs only when they are a whole 1 in N)."""
        rate = self.rate
        if rate is None and self.size is not None and self.population is not None:
            rate = whole_ratio(self.size, self.population)
        if rate is None and self.packet_interval is not None:
            if self.packet_space is None:
                rate = self.packet_interval
            else:
                rate = whole_ratio(self.packet_interval, self.packet_interval + self.packet_space)
        return rate or None


def whole_ratio(part: int, whole: int) -> int | None:
    if part == 0 or whole % part:
        return None
    ratio = whole // part
    return ratio if ratio < ERA else None


CONFLICT = "conflict"


class Exporter:
    """What an exporter's options records stated."""

    def __init__(self):
        self.rates: dict = {}
        self.init_ms: dict[int, int] = {}
        self.scopes: dict[tuple[int, int], list[dict]] = {}

    def learn(self, domain: int, extent: str, record: dict) -> None:
        if extent != "partial":
            for name, value in elements(record):
                if name == "systemInitTimeMilliseconds" and is_time(value):
                    seconds, nanos = instant(value)
                    self.init_ms[domain] = seconds * 1000 + nanos // MS
        sampling = Sampling(record)
        rate = sampling.one_in()
        if rate is None:
            return
        if extent == "system":
            self.rates["system"] = rate
        if sampling.sampler is None:
            if extent != "partial":
                self.rates["domain", domain] = rate
            return
        self.rates["sampler", domain, sampling.sampler] = rate
        self.rates["exporter sampler", sampling.sampler] = rate
        known = self.rates.get(("any sampler", domain))
        if known == CONFLICT:
            return
        self.rates["any sampler", domain] = CONFLICT if known not in (None, rate) else rate

    def rate(self, domain: int, sampler: int | None) -> int | None:
        keys = []
        if sampler is not None:
            keys += [("sampler", domain, sampler), ("exporter sampler", sampler)]
        keys += [("domain", domain), ("any sampler", domain), "system"]
        for key in keys:
            rate = self.rates.get(key)
            if rate not in (None, CONFLICT):
                return rate
        return None


def elements(record: dict):
    """A record's elements in order, an element it holds more than once
    once for each value."""
    for name, value in record.items():
        if isinstance(value, list) and not name.endswith("List"):
            for each in value:
                yield name, each
        else:
            yield name, value


def templated(base: dict, sender: str, protocol: str, packet: dict, exporter: Exporter) -> list[dict]:
    v9 = protocol == "netflow_v9"
    domain = packet["source_id"] if v9 else packet["observation_domain_id"]
    sets = packet["flow_sets"] if v9 else packet["sets"]

    # The packet's options records apply to its data records, wherever
    # they are in it.
    for flow_set in sets:
        if flow_set["type"] == "options_templates":
            for template in flow_set["templates"]:
                exporter.scopes[domain, template["template_id"]] = template["scope_fields"]
        elif flow_set["type"] == "options_data":
            scopes = exporter.scopes.get((domain, flow_set["template_id"]), [])
            for record in flow_set["records"]:
                exporter.learn(domain, extent(v9, scopes), record)

    if v9:
        export_secs, uptime = packet["unix_secs"], packet["sys_uptime"]
    else:
        export_secs = packet["export_time"]
        init_ms = exporter.init_ms.get(domain)
        uptime = (export_secs * 1000 - init_ms) % ERA if init_ms is not None and export_secs * 1000 >= init_ms else None

    flow = base | {
        "sampler_address": sender,
        "sequence_num": packet["sequence_number"],
        "observation_domain_id": domain,
    }
    out = []
    for flow_set in sets:
        if flow_set["type"] != "data":
            continue
        for record in flow_set["records"]:
            flow_record = record_flow(dict(flow), record, export_secs, uptime, exporter, domain)
            # RFC 3954 section 8: without IP_PROTOCOL_VERSION, version 4 is
            # assumed.
            if v9 and flow_record.get("etype") is None and "ipVersion" not in record:
                flow_record["etype"] = ETHER_IPV4
            out.append(flow_record)
    return out


def record_flow(flow: dict, record: dict, export_secs: int, uptime: int | None, exporter: Exporter, domain: int) -> dict:
    section = packet_section(record)
    if section is not None:
        dissect(flow, *section)

    def uptime_ns(value) -> int | None:
        n = narrow(value, 32)
        if n is None or uptime is None:
            return None
        return export_secs * NS - ((uptime - n) % ERA) * MS

    def put(key, value):
        if value is not None:
            flow[key] = value

    def fill(key, value):
        if flow.get(key) is None:
            flow[key] = value

    for name, value in elements(record):
        match name:
            case "octetDeltaCount":
                put("bytes", number(value))
            case "postOctetDeltaCount" | "octetTotalCount" | "dataLinkFrameSize":
                fill("bytes", number(value))
            case "packetDeltaCount":
                put("packets", number(value))
            case "postPacketDeltaCount" | "packetTotalCount":
                fill("packets", number(value))
            case "sourceIPv4Address" | "sourceIPv6Address":
                put("src_addr", address(value))
            case "destinationIPv4Address" | "destinationIPv6Address":
                put("dst_addr", address(value))
            case "sourceIPv4PrefixLength" | "sourceIPv6PrefixLength":
                put("src_net", narrow(value, 8))
            case "destinationIPv4PrefixLength" | "destinationIPv6PrefixLength":
                put("dst_net", narrow(value, 8))
            case "ipNextHopIPv4Address" | "ipNextHopIPv6Address":
                put("next_hop", address(value))
            case "bgpNextHopIPv4Address" | "bgpNextHopIPv6Address":
                put("bgp_next_hop", address(value))
            case "sourceMacAddress":
                put("src_mac", mac(value))
            case "destinationMacAddress":
                put("dst_mac", mac(value))
            case "postSourceMacAddress":
                fill("src_mac", mac(value))
            case "postDestinationMacAddress":
                fill("dst_mac", mac(value))
            case "ethernetType":
                put("etype", narrow(value, 16))
            case "ipVersion":
                put("etype", {4: ETHER_IPV4, 6: ETHER_IPV6}.get(number(value)))
            case "protocolIdentifier":
                put("proto", narrow(value, 8))
            case "sourceTransportPort":
                put("src_port", narrow(value, 16))
            case "destinationTransportPort":
                put("dst_port", narrow(value, 16))
            case "tcpControlBits":
                put("tcp_flags", narrow(value, 16))
            case "ipClassOfService":
                put("ip_tos", narrow(value, 8))
            case "ipTTL":
                put("ip_ttl", narrow(value, 8))
            case "minimumTTL":
                fill("ip_ttl", narrow(value, 8))
            case "flowLabelIPv6":
                put("ipv6_flow_label", narrow(value, 32))
            case "fragmentIdentification":
                put("fragment_id", narrow(value, 32))
            case "fragmentOffset":
                put("fragment_offset", narrow(value, 16))
            case "icmpTypeCodeIPv4" | "icmpTypeCodeIPv6":
                n = narrow(value, 16)
                if n is not None:
                    flow["icmp_type"], flow["icmp_code"] = n >> 8, n & 0xFF
            case "icmpTypeIPv4" | "icmpTypeIPv6":
                put("icmp_type", narrow(value, 8))
            case "icmpCodeIPv4" | "icmpCodeIPv6":
                put("icmp_code", narrow(value, 8))
            case "ingressInterface":
                put("in_if", narrow(value, 32))
            case "egressInterface":
                put("out_if", narrow(value, 32))
            case "bgpSourceAsNumber":
                put("src_as", narrow(value, 32))
            case "bgpDestinationAsNumber":
                put("dst_as", narrow(value, 32))
            case "vlanId":
                put("src_vlan", narrow(value, 16))
            case "postVlanId":
                put("dst_vlan", narrow(value, 16))
            case "forwardingStatus":
                put("forwarding_status", narrow(value, 32))
            case "flowStartSysUpTime":
                put("time_flow_start_ns", uptime_ns(value))
            case "flowEndSysUpTime":
                put("time_flow_end_ns", uptime_ns(value))
            case "flowStartSeconds" | "flowStartMilliseconds" | "flowStartMicroseconds" | "flowStartNanoseconds":
                put("time_flow_start_ns", timestamp_ns(name, value, export_secs))
            case "flowEndSeconds" | "flowEndMilliseconds" | "flowEndMicroseconds" | "flowEndNanoseconds":
                put("time_flow_end_ns", timestamp_ns(name, value, export_secs))
            case "flowStartDeltaMicroseconds":
                n = number(value)
                put("time_flow_start_ns", None if n is None else export_secs * NS - n * 1000)
            case "flowEndDeltaMicroseconds":
                n = number(value)
                put("time_flow_end_ns", None if n is None else export_secs * NS - n * 1000)

    sampling = Sampling(record)
    flow["sampling_rate"] = sampling.one_in() or exporter.rate(domain, sampling.sampler)
    if flow.get("etype") is None:
        some = flow.get("src_addr") or flow.get("dst_addr")
        if some is not None:
            flow["etype"] = ETHER_IPV4 if ipaddress.ip_address(some).version == 4 else ETHER_IPV6
    if section is not None:
        # A PSAMP packet report is about one packet.
        fill("packets", 1)
    return flow


def packet_section(record: dict) -> tuple[str, bytes] | None:
    """The first octets of a packet a PSAMP report carries, and what they
    start with."""
    frame = header = frame_type = None
    for name, value in elements(record):
        if name == "dataLinkFrameSection" and isinstance(value, str):
            frame = bytes.fromhex(value)
        elif name == "ipHeaderPacketSection" and isinstance(value, str):
            header = bytes.fromhex(value)
        elif name == "dataLinkFrameType":
            frame_type = number(value)
        elif name == "sectionOffset" and number(value) != 0:
            return None
    if frame is not None and frame_type in (None, 1):
        return "ethernet", frame
    if not header:
        return None
    return {4: ("ipv4", header), 6: ("ipv6", header)}.get(header[0] >> 4)


# sFlow v5.

INTERNAL = 0x3FFF_FFFF


def sflow_v5(base: dict, packet: dict) -> list[dict]:
    out = []
    for sample in packet["samples"]:
        if sample["type"] not in ("flow", "expanded_flow"):
            continue
        compact = sample["type"] == "flow"

        def interface(i: dict) -> int | None:
            known = i["format"] == 0 and i["value"] != 0 and not (compact and i["value"] == INTERNAL)
            return i["value"] if known else None

        flow = base | {
            "sampler_address": packet.get("agent_address", "0.0.0.0"),
            "sequence_num": packet["sequence_number"],
            "sampling_rate": sample["sampling_rate"] or None,
            "in_if": interface(sample["input"]),
            "out_if": interface(sample["output"]),
            "packets": 1,
        }
        for record in sample["records"]:
            sflow_record(flow, record)
        out.append(flow)
    return out


def sflow_record(flow: dict, record: dict) -> None:
    def fill(key, value, bits=None):
        if flow.get(key) is None:
            flow[key] = value if bits is None or value < 1 << bits else None

    def fits(value, bits, key):
        """`value` if it fits, else what the flow had."""
        return value if value < 1 << bits else flow.get(key)

    match record["type"]:
        case "sampled_header":
            flow["bytes"] = record["frame_length"]
            # An unassigned protocol prints as {"Unassigned": number}.
            protocol = record["protocol"] if isinstance(record["protocol"], str) else None
            start = {"EthernetIso88023": "ethernet", "Ipv4": "ipv4", "Ipv6": "ipv6"}.get(protocol)
            if start is not None:
                dissect(flow, start, bytes.fromhex(record["header"]))
        case "sampled_ethernet":
            fill("bytes", record["length"])
            fill("src_mac", record["src_mac"])
            fill("dst_mac", record["dst_mac"])
            fill("etype", record["ether_type"], 16)
        case "sampled_ipv4" | "sampled_ipv6":
            v4 = record["type"] == "sampled_ipv4"
            fill("bytes", record["length"])
            fill("etype", ETHER_IPV4 if v4 else ETHER_IPV6)
            fill("src_addr", record["src_ip"])
            fill("dst_addr", record["dst_ip"])
            fill("proto", record["protocol"], 8)
            fill("src_port", record["src_port"], 16)
            fill("dst_port", record["dst_port"], 16)
            fill("tcp_flags", record["tcp_flags"], 16)
            if v4:
                fill("ip_tos", record["tos"], 8)
        case "extended_switch":
            # 0xFFFFFFFF, an unknown VLAN, does not fit.
            flow["src_vlan"] = fits(record["src_vlan"], 16, "src_vlan")
            flow["dst_vlan"] = fits(record["dst_vlan"], 16, "dst_vlan")
        case "extended_router":
            flow["next_hop"] = record.get("nexthop", flow.get("next_hop"))
            flow["src_net"] = fits(record["src_mask_len"], 8, "src_net")
            flow["dst_net"] = fits(record["dst_mask_len"], 8, "dst_net")
        case "extended_gateway":
            flow["bgp_next_hop"] = record.get("nexthop", flow.get("bgp_next_hop"))
            flow["src_as"] = record["src_as"]
            # The destination is the last AS of an ordered last segment.
            path = record["dst_as_path"]
            last = path[-1] if path else {}
            sequence = last.get("AsSequence")
            if sequence:
                flow["dst_as"] = sequence[-1]


# Sampled packets, down to the transport header. What is cut off reads as
# absent.


def u16(data: bytes, at: int) -> int | None:
    return int.from_bytes(data[at : at + 2], "big") if len(data) >= at + 2 else None


def byte(data: bytes, at: int) -> int | None:
    return data[at] if len(data) > at else None


def octets(data: bytes, at: int, length: int) -> bytes | None:
    return data[at : at + length] if len(data) >= at + length else None


def after_ether_type(ether_type: int | None) -> str | None:
    if ether_type is None:
        return None
    if ether_type in (0x8100, 0x88A8, 0x9100):
        return "vlan"
    if ether_type in (0x8847, 0x8848, 0x6558):
        raise NotImplementedError(f"EtherType {ether_type:#06x} in a sampled header")
    return {ETHER_IPV4: "ipv4", ETHER_IPV6: "ipv6"}.get(ether_type, "other")


def after_ip(protocol: int | None) -> str | None:
    if protocol is None:
        return None
    if protocol in (47, 137):
        raise NotImplementedError(f"IP protocol {protocol} in a sampled header")
    return {1: "icmp", 4: "ipv4", 6: "tcp", 17: "udp", 41: "ipv6", 58: "icmp"}.get(protocol, "other")


# IPv6 extension headers, by how their length is given.
EXTENSIONS_IN_8 = {0, 43, 60, 135, 139, 140}
AUTHENTICATION, FRAGMENT = 51, 44


def ipv6_payload(data: bytes, next_header: int) -> tuple[int | str | None, bytes]:
    """The protocol after the extension headers, and the octets after them;
    `None` when they are cut off, "fragment" past a later fragment."""
    while True:
        if next_header in EXTENSIONS_IN_8 or next_header == AUTHENTICATION:
            if len(data) < 2:
                return None, data
            length = (data[1] + 1) * 8 if next_header != AUTHENTICATION else (data[1] + 2) * 4
        elif next_header == FRAGMENT:
            length = 8
        else:
            return next_header, data
        if len(data) < length:
            return None, data
        header, data = data[:length], data[length:]
        if next_header == FRAGMENT and int.from_bytes(header[2:4], "big") >> 3:
            return "fragment", data
        next_header = header[0]


def dissect(flow: dict, protocol: str, data: bytes) -> None:
    def take(length: int) -> bytes:
        nonlocal data
        header, data = data[:length], data[length:]
        return header

    def assign(key, value):
        flow[key] = value

    while True:
        if protocol == "ethernet":
            h = take(14)
            dst, src = octets(h, 0, 6), octets(h, 6, 6)
            assign("dst_mac", dst and ":".join(f"{b:02x}" for b in dst))
            assign("src_mac", src and ":".join(f"{b:02x}" for b in src))
            assign("etype", u16(h, 12))
            protocol = after_ether_type(u16(h, 12))
        elif protocol == "vlan":
            h = take(4)
            tci = u16(h, 0)
            if flow.get("src_vlan") is None and tci is not None:
                flow["src_vlan"] = tci & 0x0FFF
            ether_type = u16(h, 2)
            if ether_type is not None:
                flow["etype"] = ether_type
            protocol = after_ether_type(ether_type)
        elif protocol == "ipv4":
            first = byte(data, 0)
            length = (first & 0x0F) * 4 if first is not None and (first & 0x0F) * 4 >= 20 else 20
            h = take(length)
            offset = u16(h, 6)
            offset = None if offset is None else offset & 0x1FFF
            assign("etype", ETHER_IPV4)
            assign("src_addr", address(octets(h, 12, 4)) if octets(h, 12, 4) else None)
            assign("dst_addr", address(octets(h, 16, 4)) if octets(h, 16, 4) else None)
            assign("proto", byte(h, 9))
            assign("ip_tos", byte(h, 1))
            assign("ip_ttl", byte(h, 8))
            assign("fragment_id", u16(h, 4))
            assign("fragment_offset", offset)
            assign("ipv6_flow_label", None)
            protocol = None if offset is None or offset != 0 else after_ip(byte(h, 9))
        elif protocol == "ipv6":
            h = take(40)
            payload, data = ipv6_payload(data, h[6]) if len(h) == 40 else (None, data)
            word = octets(h, 0, 4)
            assign("etype", ETHER_IPV6)
            assign("src_addr", address(octets(h, 8, 16)) if octets(h, 8, 16) else None)
            assign("dst_addr", address(octets(h, 24, 16)) if octets(h, 24, 16) else None)
            assign("proto", payload if isinstance(payload, int) else None)
            assign("ip_tos", (u16(h, 0) >> 4) & 0xFF if u16(h, 0) is not None else None)
            assign("ip_ttl", byte(h, 7))
            assign("ipv6_flow_label", int.from_bytes(word, "big") & 0xFFFFF if word else None)
            assign("fragment_id", None)
            assign("fragment_offset", None)
            protocol = after_ip(payload) if isinstance(payload, int) else None
        elif protocol == "udp":
            h = take(8)
            if u16(h, 2) in (4789, 6081):
                raise NotImplementedError("a UDP tunnel in a sampled header")
            assign("src_port", u16(h, 0))
            assign("dst_port", u16(h, 2))
            return
        elif protocol == "tcp":
            h = take(20)
            assign("src_port", u16(h, 0))
            assign("dst_port", u16(h, 2))
            assign("tcp_flags", byte(h, 13))
            return
        elif protocol == "icmp":
            h = take(4)
            assign("icmp_type", byte(h, 0))
            assign("icmp_code", byte(h, 1))
            return
        else:
            return
