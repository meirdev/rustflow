use std::net::Ipv4Addr;

use serde::Serialize;

pub const NETFLOW_V5_VERSION: u16 = 5;

/// Represents a NetFlow Version 5 packet.
/// A NetFlow V5 packet consists of a header and one or more flow records.
#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV5 {
    /// The header of the NetFlow V5 packet.
    pub header: Header,
    /// A vector of flow records. Each record represents a flow.
    pub flow_records: Vec<FlowRecord>,
}

/// Represents the header of a NetFlow Version 5 packet.
#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// NetFlow export format version number (should be 5).
    pub version: u16,
    /// Number of flows exported in this packet (1 to 30).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen.
    pub flow_sequence: u32,
    /// Type of flow-switching engine.
    pub engine_type: u8,
    /// Slot number of the flow-switching engine.
    pub engine_id: u8,
    /// The most significant 2 bits are used for sampling mode.
    pub sampling_mode: u16, // 2 bits
    /// The least significant 14 bits are used for sampling interval.
    pub sampling_interval: u16, // 14 bits
}

/// Represents a single flow record in a NetFlow Version 5 packet.
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
    /// Unused (zero) bytes.
    pub pad1: u8,
    /// Cumulative OR of TCP flags.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17).
    pub prot: u8,
    /// IP type of service (ToS).
    pub tos: u8,
    /// Autonomous system number of the source, either origin or peer.
    pub src_as: u16,
    /// Autonomous system number of the destination, either origin or peer.
    pub dst_as: u16,
    /// Source address prefix mask bits.
    pub src_mask: u8,
    /// Destination address prefix mask bits.
    pub dst_mask: u8,
    /// Unused (zero) bytes.
    pub pad2: u16,
}
