//! NetFlow v5: a fixed 24-byte header followed by `count` fixed 48-byte flow
//! records.

use std::net::Ipv4Addr;

pub use parser::parse;
pub use writer::write;

use crate::protocol::WriteError;

mod parser;
#[cfg(test)]
mod tests;
mod writer;

pub const VERSION: u16 = 5;

/// The low 14 bits of the sampling field.
const SAMPLING_INTERVAL_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

/// The packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// NetFlow export format version number.
    pub version: u16,
    /// Number of flows exported in this packet.
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
    /// Sampling mode and interval.
    pub sampling_interval: Sampling,
}

/// The header's 16-bit `sampling_interval` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sampling {
    /// The first two bits.
    pub mode: u8,
    /// The remaining 14 bits: one of every `interval` packets is sampled.
    pub interval: u16,
}

impl From<u16> for Sampling {
    fn from(field: u16) -> Self {
        Self {
            mode: field.to_be_bytes()[0] >> 6,
            interval: field & SAMPLING_INTERVAL_MASK,
        }
    }
}

impl TryFrom<Sampling> for u16 {
    type Error = WriteError;

    fn try_from(sampling: Sampling) -> Result<Self, WriteError> {
        if sampling.mode > 3 {
            return Err(WriteError::TooLarge {
                field: "sampling mode",
                value: usize::from(sampling.mode),
            });
        }
        if sampling.interval > SAMPLING_INTERVAL_MASK {
            return Err(WriteError::TooLarge {
                field: "sampling interval",
                value: usize::from(sampling.interval),
            });
        }
        Ok((u16::from(sampling.mode) << 14) | sampling.interval)
    }
}

/// A flow record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowRecord {
    /// Source IP address.
    pub srcaddr: Ipv4Addr,
    /// Destination IP address.
    pub dstaddr: Ipv4Addr,
    /// IP address of the next hop router.
    pub nexthop: Ipv4Addr,
    /// SNMP index of the input interface.
    pub input: u16,
    /// SNMP index of the output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_octets: u32,
    /// `sys_uptime` at the start of the flow.
    pub first: u32,
    /// `sys_uptime` when the last packet of the flow was received.
    pub last: u32,
    /// TCP/UDP source port number or equivalent.
    pub srcport: u16,
    /// TCP/UDP destination port number or equivalent.
    pub dstport: u16,
    /// Cumulative OR of TCP flags.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6, UDP = 17).
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
}
