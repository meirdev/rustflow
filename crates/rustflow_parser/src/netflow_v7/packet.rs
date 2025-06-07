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
    /// Number of flows exported in this flow frame (protocol data unit, or
    /// PDU).
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
    /// Source IP address; in case of destination-only flows, set to zero.
    pub srcaddr: Ipv4Addr,
    /// Destination IP address.
    pub dstaddr: Ipv4Addr,
    /// Next hop router; always set to zero.
    pub nexthop: Ipv4Addr,
    /// SNMP index of input interface; always set to zero.
    pub input: u16,
    /// SNMP index of output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_ockts: u32,
    /// SysUptime, in milliseconds, at the start of flow.
    pub first: u32,
    /// SysUptime, in milliseconds, at the time the last packet of the flow was
    /// received.
    pub last: u32,
    /// TCP/UDP source port number; set to zero if flow mask is destination-only
    /// or source-destination.
    pub srcport: u16,
    /// TCP/UDP destination port number; set to zero if flow mask is
    /// destination-only or source-destination.
    pub dstport: u16,
    /// Flags indicating, among other things, what flow fields are invalid.
    pub flags1: u8,
    /// TCP flags; always set to zero.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17); set to zero if flow
    /// mask is destination-only or source-destination.
    pub prot: u8,
    /// IP type of service; switch sets it to the ToS of the first packet of the
    /// flow.
    pub tos: u8,
    /// Source autonomous system number, either origin or peer; always set to
    /// zero.
    pub src_as: u16,
    /// Destination autonomous system number, either origin or peer; always set
    /// to zero.
    pub dst_as: u16,
    /// Source address prefix mask; always set to zero.
    pub src_mask: u8,
    /// Destination address prefix mask; always set to zero.
    pub dst_mask: u8,
    /// Flags indicating, among other things, what flows are invalid.
    pub flags2: u16,
    /// IP address of the router that is bypassed by the Catalyst 5000 series
    /// switch. This is the same address the router uses when it sends NetFlow
    /// export packets. This IP address is propagated to all switches bypassing
    /// the router through the FCP protocol.
    pub router_sc: u32,
}
