use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, map, map_opt, verify};
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};

use crate::netflow::v5_types::{FlowRecord, Message};

pub const NETFLOW_V5_VERSION: u16 = 5;

fn parse_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |t| DateTime::<Utc>::from_timestamp_millis(t as i64)).parse(input)
}

pub fn parse_message(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V5_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = parse_timestamp(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    let sampling_mode = sampling_interval >> 14;
    let sampling_interval = sampling_interval & 0x3fff;

    let (input, flow_records) =
        all_consuming(many(count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        Message {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            engine_type,
            engine_id,
            sampling_mode,
            sampling_interval,
            flow_records,
        },
    ))
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = parse_ipv4_addr(input)?;
    let (input, dstaddr) = parse_ipv4_addr(input)?;
    let (input, nexthop) = parse_ipv4_addr(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
    let (input, first) = parse_timestamp(input)?;
    let (input, last) = parse_timestamp(input)?;
    let (input, srcport) = be_u16(input)?;
    let (input, dstport) = be_u16(input)?;
    let (input, _) = take(1usize)(input)?;
    let (input, tcp_flags) = be_u8(input)?;
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, src_as) = be_u16(input)?;
    let (input, dst_as) = be_u16(input)?;
    let (input, src_mask) = be_u8(input)?;
    let (input, dst_mask) = be_u8(input)?;
    let (input, _) = take(2usize)(input)?;

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
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
        },
    ))
}
