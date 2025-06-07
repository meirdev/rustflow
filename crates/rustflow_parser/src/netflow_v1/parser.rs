use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Parser;
use nom::{IResult, ToUsize};

use crate::netflow_v1::packet::{FlowRecord, Header, NetFlowV1, NETFLOW_V1_VERSION};

pub struct NetFlowV1Parser;

impl Default for NetFlowV1Parser {
    fn default() -> Self {
        NetFlowV1Parser
    }
}

impl NetFlowV1Parser {
    pub fn parse<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV1> {
        parse_netflow_v1(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V1_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
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
    let (input, _) = take(1usize)(input)?; // pad1
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, flags) = be_u8(input)?;
    let (input, _) = take(3usize)(input)?; // pad1, pad2, pad3
    let (input, _) = take(4usize)(input)?; // reserved

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
            prot,
            tos,
            flags,
        },
    ))
}

fn parse_netflow_v1(input: &[u8]) -> IResult<&[u8], NetFlowV1> {
    let (input, header) = parse_header(input)?;
    let (input, flow_records) =
        all_consuming(many(0..=header.count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV1 {
            header,
            flow_records,
        },
    ))
}
