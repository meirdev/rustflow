use std::net::Ipv4Addr;

use winnow::binary::{be_u16, be_u32, u8};
use winnow::combinator::{repeat, seq};
use winnow::error::{StrContext, StrContextValue};
use winnow::{Parser as _, Result};

use super::*;

impl From<u16> for Sampling {
    fn from(field: u16) -> Self {
        Self {
            mode: field.to_be_bytes()[0] >> 6,
            interval: field & SAMPLING_INTERVAL_MASK,
        }
    }
}

pub fn parse(input: &[u8]) -> Result<Packet> {
    let mut input = input;
    let header = parse_header(&mut input)?;
    let flow_records = repeat(usize::from(header.count), parse_flow_record)
        .context(StrContext::Label("flow records"))
        .parse_next(&mut input)?;

    Ok(Packet {
        header,
        flow_records,
    })
}

fn parse_header(input: &mut &[u8]) -> Result<Header> {
    seq!(Header {
        version: be_u16
            .verify(|&version| version == VERSION)
            .context(StrContext::Label("version"))
            .context(StrContext::Expected(StrContextValue::Description("5"))),
        count: be_u16,
        sys_uptime: be_u32,
        unix_secs: be_u32,
        unix_nsecs: be_u32,
        flow_sequence: be_u32,
        engine_type: u8,
        engine_id: u8,
        sampling_interval: be_u16.map(Sampling::from),
    })
    .parse_next(input)
}

fn parse_flow_record(input: &mut &[u8]) -> Result<FlowRecord> {
    seq!(FlowRecord {
        srcaddr: ipv4,
        dstaddr: ipv4,
        nexthop: ipv4,
        input: be_u16,
        output: be_u16,
        d_pkts: be_u32,
        d_octets: be_u32,
        first: be_u32,
        last: be_u32,
        srcport: be_u16,
        dstport: be_u16,
        _: u8, // pad1
        tcp_flags: u8,
        prot: u8,
        tos: u8,
        src_as: be_u16,
        dst_as: be_u16,
        src_mask: u8,
        dst_mask: u8,
        _: be_u16, // pad2
    })
    .parse_next(input)
}

fn ipv4(input: &mut &[u8]) -> Result<Ipv4Addr> {
    be_u32.map(Ipv4Addr::from).parse_next(input)
}
