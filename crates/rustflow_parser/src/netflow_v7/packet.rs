use std::net::Ipv4Addr;

use serde::Serialize;

pub const NETFLOW_V7_VERSION: u16 = 7;

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV7 {
    /// The header of the NetFlow V7 packet.
    pub header: Header,
    /// A vector of flow records. Each record represents a flow.
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// NetFlow export format version number (should be 7).
    pub version: u16,
    /// Number of flows exported in this packet (1-30).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen.
    pub flow_sequence: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRecord {
    /// Source IP address.
    pub srcaddr: Ipv4Addr,
    /// Destination IP address.
    pub dstaddr: Ipv4Addr,
    /// IP address of next hop router.
    pub nexthop: Ipv4Addr,
    /// SNMP index of input interface.
    pub input: u16,
    /// SNMP index of output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_ockts: u32,
    /// SysUptime at start of flow.
    pub first: u32,
    /// SysUptime at the time the last packet of the flow was received.
    pub last: u32,
    /// TCP/UDP source port number or equivalent.
    pub srcport: u16,
    /// TCP/UDP destination port number or equivalent.
    pub dstport: u16,
    /// Flags indicating, among other things, what flow fields are invalid.
    pub flags1: u8,
    /// Cumulative OR of TCP flags.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17).
    pub prot: u8,
    /// IP type of service (ToS).
    pub tos: u8,
    /// Source autonomous system number, either origin or peer.
    pub src_as: u16,
    /// Destination autonomous system number, either origin or peer.
    pub dst_as: u16,
    /// Source address prefix mask bits.
    pub src_mask: u8,
    /// Destination address prefix mask bits.
    pub dst_mask: u8,
    /// Flags indicating, among other things, what flows are invalid.
    pub flags2: u16,
    /// IP address of the router that is bypassed by the Catalyst 5000 series
    /// switch. This is the same address the router uses when it sends NetFlow
    /// export packets. This IP address is propagated to all switches bypassing
    /// the router through the FCP protocol.
    pub router_sc: u32,
}
