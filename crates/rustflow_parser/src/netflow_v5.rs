use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Parser;
use nom::{IResult, ToUsize};

use rustflow_types::netflow_v5::{FlowRecord, Header, NetFlowV5, NETFLOW_V5_VERSION};

pub struct NetFlowV5Parser;

impl Default for NetFlowV5Parser {
    fn default() -> Self {
        NetFlowV5Parser
    }
}

impl NetFlowV5Parser {
    pub fn parse(self, input: &[u8]) -> IResult<&[u8], NetFlowV5> {
        parse_netflow_v5(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V5_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sysuptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sysuptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            engine_type,
            engine_id,
            sampling_interval,
        },
    ))
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = take(4u8)(input)?;
    let (input, dstaddr) = take(4u8)(input)?;
    let (input, nexthop) = take(4u8)(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, dpkts) = be_u32(input)?;
    let (input, dockts) = be_u32(input)?;
    let (input, first) = be_u32(input)?;
    let (input, last) = be_u32(input)?;
    let (input, srcport) = be_u16(input)?;
    let (input, dstport) = be_u16(input)?;
    let (input, pad1) = be_u8(input)?;
    let (input, tcp_flags) = be_u8(input)?;
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, src_as) = be_u16(input)?;
    let (input, dst_as) = be_u16(input)?;
    let (input, src_mask) = be_u8(input)?;
    let (input, dst_mask) = be_u8(input)?;
    let (input, pad2) = be_u16(input)?;

    Ok((
        input,
        FlowRecord {
            srcaddr: [srcaddr[0], srcaddr[1], srcaddr[2], srcaddr[3]],
            dstaddr: [dstaddr[0], dstaddr[1], dstaddr[2], dstaddr[3]],
            nexthop: [nexthop[0], nexthop[1], nexthop[2], nexthop[3]],
            input: input_,
            output,
            dpkts,
            dockts,
            first,
            last,
            srcport,
            dstport,
            pad1,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            pad2,
        },
    ))
}

fn parse_netflow_v5(input: &[u8]) -> IResult<&[u8], NetFlowV5> {
    let (input, header) = parse_header(input)?;
    let (input, flow_records) =
        all_consuming(many(0..=header.count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV5 {
            header,
            flow_records,
        },
    ))
}
