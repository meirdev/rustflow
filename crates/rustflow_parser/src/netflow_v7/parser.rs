use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Parser;
use nom::{IResult, ToUsize};

use crate::netflow_v7::packet::{FlowRecord, Header, NetFlowV7, NETFLOW_V7_VERSION};

pub struct NetFlowV7Parser;

impl Default for NetFlowV7Parser {
    fn default() -> Self {
        NetFlowV7Parser
    }
}

impl NetFlowV7Parser {
    pub fn parse<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV7> {
        parse_netflow_v7(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V7_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, reserved) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            reserved,
        },
    ))
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = be_u32(input)?;
    let (input, dstaddr) = be_u32(input)?;
    let (input, nexthop) = be_u32(input)?;
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
    let (input, router_sc) = be_u32(input)?;

    Ok((
        input,
        FlowRecord {
            srcaddr: srcaddr.into(),
            dstaddr: dstaddr.into(),
            nexthop: nexthop.into(),
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

fn parse_netflow_v7(input: &[u8]) -> IResult<&[u8], NetFlowV7> {
    let (input, header) = parse_header(input)?;
    let (input, flow_records) =
        all_consuming(many(0..=header.count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV7 {
            header,
            flow_records,
        },
    ))
}
