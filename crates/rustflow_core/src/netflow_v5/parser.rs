use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::combinator::map_opt;
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use serde::Serialize;

use crate::common::parser::{ipv4_addr, verify_version};

pub const NETFLOW_V5_VERSION: u16 = 5;

pub struct NetFlowV5Parser;

impl NetFlowV5Parser {
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV5Packet> {
        let (input, header) = parse_header(input)?;
        let (input, flow_records) =
            many(header.count.to_usize(), parse_flow_record).parse(input)?;

        Ok((
            input,
            NetFlowV5Packet {
                header,
                flow_records,
            },
        ))
    }
}

impl Default for NetFlowV5Parser {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV5Packet {
    #[serde(flatten)]
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: DateTime<Utc>,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u16,
    pub sampling_interval: u16,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify_version(input, NETFLOW_V5_VERSION)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = timestamp_millis(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    let sampling_mode = sampling_interval >> 14;
    let sampling_interval = sampling_interval & 0x3fff;

    Ok((
        input,
        Header {
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
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRecord {
    pub srcaddr: Ipv4Addr,
    pub dstaddr: Ipv4Addr,
    pub nexthop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_ockts: u32,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub srcport: u16,
    pub dstport: u16,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = ipv4_addr(input)?;
    let (input, dstaddr) = ipv4_addr(input)?;
    let (input, nexthop) = ipv4_addr(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
    let (input, first) = timestamp_millis(input)?;
    let (input, last) = timestamp_millis(input)?;
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

// NetFlow v5 stores milliseconds in an unsigned 32-bit integer.
// Apparently, the protocol suffers from the same bugs noted on Wikipedia (https://en.wikipedia.org/wiki/Time_formatting_and_storage_bugs) that affect other software.
fn timestamp_millis(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |v| DateTime::<Utc>::from_timestamp_millis(v as i64)).parse(input)
}
