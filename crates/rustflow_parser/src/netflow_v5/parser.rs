use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Parser;
use nom::{IResult, ToUsize};

use crate::netflow_v5::packet::{FlowRecord, Header, NetFlowV5, NETFLOW_V5_VERSION};

pub struct NetFlowV5Parser;

impl Default for NetFlowV5Parser {
    fn default() -> Self {
        NetFlowV5Parser
    }
}

impl NetFlowV5Parser {
    pub fn parse<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV5> {
        parse_netflow_v5(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V5_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    let sampling_mode = (sampling_interval >> 14) as u8;
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

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, srcaddr) = take(4u8)(input)?;
    let (input, dstaddr) = take(4u8)(input)?;
    let (input, nexthop) = take(4u8)(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
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
            srcaddr: Ipv4Addr::from([srcaddr[0], srcaddr[1], srcaddr[2], srcaddr[3]]),
            dstaddr: Ipv4Addr::from([dstaddr[0], dstaddr[1], dstaddr[2], dstaddr[3]]),
            nexthop: Ipv4Addr::from([nexthop[0], nexthop[1], nexthop[2], nexthop[3]]),
            input: input_,
            output,
            d_pkts,
            d_ockts,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_netflow_v5() {
        let input: &[u8] = &[
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x8a, 0x04, 0x68, 0x3b, 0xb0, 0x84, 0x2b, 0x06,
            0xbd, 0x70, 0x00, 0x00, 0x00, 0x31, 0x01, 0x00, 0x00, 0x00, 0x70, 0x0a, 0x14, 0x0a,
            0xac, 0x1e, 0xbe, 0x0a, 0xac, 0xc7, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0xe1, 0x00, 0x00, 0x02, 0x63, 0x00, 0x00, 0x87, 0x78, 0x00, 0x00, 0x88, 0xc3,
            0x00, 0x28, 0x00, 0x50, 0x00, 0x00, 0x06, 0x00, 0x14, 0xd7, 0x9d, 0x02, 0x07, 0x1e,
            0x00, 0x00,
        ];

        let result = NetFlowV5Parser::default().parse(input);

        let (_, netflow) = result.unwrap();

        assert_eq!(netflow.header.version, NETFLOW_V5_VERSION);
        assert_eq!(netflow.header.count, 1);
        assert_eq!(netflow.header.sys_uptime, 35332);
        assert_eq!(netflow.header.unix_secs, 1748742276);
        assert_eq!(netflow.header.unix_nsecs, 721862000);
        assert_eq!(netflow.header.flow_sequence, 49);
        assert_eq!(netflow.header.engine_type, 1);
        assert_eq!(netflow.header.engine_id, 0);
        assert_eq!(netflow.header.sampling_mode, 0);
        assert_eq!(netflow.header.sampling_interval, 0);

        let flow_record = &netflow.flow_records[0];

        assert_eq!(flow_record.srcaddr.to_string(), "112.10.20.10");
        assert_eq!(flow_record.dstaddr.to_string(), "172.30.190.10");
        assert_eq!(flow_record.nexthop.to_string(), "172.199.15.1");
        assert_eq!(flow_record.input, 0);
        assert_eq!(flow_record.output, 0);
        assert_eq!(flow_record.d_pkts, 993);
        assert_eq!(flow_record.d_ockts, 611);
        assert_eq!(flow_record.first, 34680);
        assert_eq!(flow_record.last, 35011);
        assert_eq!(flow_record.srcport, 40);
        assert_eq!(flow_record.dstport, 80);
        assert_eq!(flow_record.pad1, 0);
        assert_eq!(flow_record.tcp_flags, 0);
        assert_eq!(flow_record.prot, 6);
        assert_eq!(flow_record.tos, 0);
        assert_eq!(flow_record.src_as, 5335);
        assert_eq!(flow_record.dst_as, 40194);
        assert_eq!(flow_record.src_mask, 7);
        assert_eq!(flow_record.dst_mask, 30);
        assert_eq!(flow_record.pad2, 0);
    }
}
