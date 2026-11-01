use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use serde::Serialize;

use crate::common::parser::{ipv4_addr, verify_version};

pub const NETFLOW_V5_VERSION: u16 = 5;

pub struct NetFlowV5Parser;

impl NetFlowV5Parser {
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV5Packet> {
        parse_netflow_v5_packet(input)
    }
}

impl Default for NetFlowV5Parser {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetFlowV5Packet {
    #[serde(flatten)]
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

fn parse_netflow_v5_packet(input: &[u8]) -> IResult<&[u8], NetFlowV5Packet> {
    let (input, header) = parse_header(input)?;
    let (input, flow_records) = many(header.count.to_usize(), parse_flow_record).parse(input)?;

    Ok((
        input,
        NetFlowV5Packet {
            header,
            flow_records,
        },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u16,
    pub sampling_interval: u16,
}

impl Header {
    pub fn unix_time(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(i64::from(self.unix_secs), self.unix_nsecs)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify_version(input, NETFLOW_V5_VERSION)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowRecord {
    pub srcaddr: Ipv4Addr,
    pub dstaddr: Ipv4Addr,
    pub nexthop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_ockts: u32,
    pub first: u32,
    pub last: u32,
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
    let (input, first) = be_u32(input)?;
    let (input, last) = be_u32(input)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::encoder::Encode;

    #[test]
    fn uptimes_are_milliseconds_since_boot_and_encode_back() {
        // An exporter up for an hour; one flow seen from 60 s to 1 s before.
        let header = [
            &5u16.to_be_bytes()[..],
            &1u16.to_be_bytes(),
            &3_600_000u32.to_be_bytes(),
            &1_700_000_000u32.to_be_bytes(),
            &0u32.to_be_bytes(),
            &42u32.to_be_bytes(),
            &[0, 0],
            &0u16.to_be_bytes(),
        ]
        .concat();
        let record = [
            &[192, 0, 2, 1, 198, 51, 100, 1, 0, 0, 0, 0][..],
            &1u16.to_be_bytes(),
            &2u16.to_be_bytes(),
            &10u32.to_be_bytes(),
            &1500u32.to_be_bytes(),
            &3_540_000u32.to_be_bytes(),
            &3_599_000u32.to_be_bytes(),
            &1234u16.to_be_bytes(),
            &80u16.to_be_bytes(),
            &[0, 0x18, 6, 0],
            &[0; 8],
        ]
        .concat();
        let bytes = [header, record].concat();

        let (_, packet) = NetFlowV5Parser.parse(&bytes).unwrap();
        assert_eq!(packet.header.sys_uptime, 3_600_000);
        assert_eq!(packet.flow_records[0].first, 3_540_000);
        assert_eq!(packet.flow_records[0].last, 3_599_000);

        let mut encoded = Vec::new();
        packet.encode(&mut encoded);
        assert_eq!(encoded, bytes);
    }
}
