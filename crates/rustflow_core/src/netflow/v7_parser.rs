use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use serde::Serialize;

use crate::netflow::common::parse_ipv4_addr;

pub const NETFLOW_V7_VERSION: u16 = 7;

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV7 {
    /// NetFlow export format version number (should be 7).
    pub version: u16,
    /// Number of flows exported in this flow frame (protocol data unit, or
    /// PDU).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen.
    pub flow_sequence: u32,
    /// A vector of flow records. Each record represents a flow.
    pub flow_records: Vec<FlowRecord>,
}

impl<'a> TryFrom<&'a [u8]> for NetFlowV7 {
    type Error = nom::Err<nom::error::Error<&'a [u8]>>;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        let (_, netflow_v5) = parse_netflow_v7.parse(input)?;

        Ok(netflow_v5)
    }
}

fn parse_netflow_v7(input: &[u8]) -> IResult<&[u8], NetFlowV7> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V7_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, _) = take(4usize)(input)?; // reserved
    let (input, flow_records) =
        all_consuming(many(count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV7 {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            flow_records,
        },
    ))
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
    pub router_sc: Ipv4Addr,
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = parse_ipv4_addr(input)?;
    let (input, dstaddr) = parse_ipv4_addr(input)?;
    let (input, nexthop) = parse_ipv4_addr(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
    let (input, first) = be_u32(input)?;
    let (input, last) = be_u32(input)?;
    let (input, srcport) = be_u16(input)?;
    let (input, dstport) = be_u16(input)?;
    let (input, flags1) = be_u8(input)?;
    let (input, tcp_flags) = be_u8(input)?;
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, src_as) = be_u16(input)?;
    let (input, dst_as) = be_u16(input)?;
    let (input, src_mask) = be_u8(input)?;
    let (input, dst_mask) = be_u8(input)?;
    let (input, flags2) = be_u16(input)?;
    let (input, router_sc) = parse_ipv4_addr(input)?;

    Ok((
        input,
        FlowRecord {
            srcaddr,
            dstaddr,
            nexthop,
            input: input_,
            output,
            d_pkts,
            d_ockts,
            first,
            last,
            srcport,
            dstport,
            flags1,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            flags2,
            router_sc,
        },
    ))
}
