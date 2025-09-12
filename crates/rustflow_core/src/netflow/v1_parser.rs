use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use serde::Serialize;

use crate::netflow::common::parse_ipv4_addr;

pub const NETFLOW_V1_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV1 {
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
    /// A vector of flow records. Each record represents a flow.
    pub flow_records: Vec<FlowRecord>,
}

impl<'a> TryFrom<&'a [u8]> for NetFlowV1 {
    type Error = nom::Err<nom::error::Error<&'a [u8]>>;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        let (_, netflow_v5) = parse_netflow_v1(input)?;

        Ok(netflow_v5)
    }
}

fn parse_netflow_v1(input: &[u8]) -> IResult<&[u8], NetFlowV1> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V1_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_records) =
        all_consuming(many(count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV1 {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
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
    /// Total number of Layer 3 octets in the packets of the flow.
    pub d_ockts: u32,
    /// SysUptime, in milliseconds, at start of flow.
    pub first: u32,
    /// SysUptime, in milliseconds, at the time the last packet of the flow was
    /// received.
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
    let (input, _) = take(1usize)(input)?; // pad1
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, flags) = be_u8(input)?;
    let (input, _) = take(3usize)(input)?; // pad1, pad2, pad3
    let (input, _) = take(4usize)(input)?; // reserved

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
            prot,
            tos,
            flags,
        },
    ))
}
