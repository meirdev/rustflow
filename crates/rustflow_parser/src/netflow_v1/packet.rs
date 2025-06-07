use std::net::Ipv4Addr;

use serde::Serialize;

pub const NETFLOW_V1_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV1 {
    /// The header of the NetFlow V1 packet.
    pub header: Header,
    /// A vector of flow records. Each record represents a flow.
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// NetFlow export format version number (should be 1).
    pub version: u16,
    /// Number of flows exported in this packet (1-24).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
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
    /// Total number of Layer 3 octets in the packets of the flow.
    pub d_ockts: u32,
    /// SysUptime at start of flow.
    pub first: u32,
    /// SysUptime at the time the last packet of the flow was received.
    pub last: u32,
    /// TCP/UDP source port number or equivalent.
    pub srcport: u16,
    /// TCP/UDP destination port number or equivalent.
    pub dstport: u16,
    /// IP protocol type (for example, TCP = 6; UDP = 17).
    pub prot: u8,
    /// IP type of service (ToS).
    pub tos: u8,
    /// Cumulative OR of TCP flags.
    pub flags: u8,
}
