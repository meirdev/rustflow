use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{fail, map, map_res, peek, verify};
use nom::error::Error;
use nom::multi::{many, many1};
use nom::number::complete::{be_i32, be_u32, be_u64, be_u128};
use nom::{IResult, Parser};
use rustc_hash::FxHashMap;

use crate::sflow::types::{
    AsPathSegmentType, AsPathType, CounterRecord, CounterRecordType, CounterSample, CounterType,
    DataValue, Direction, EthernetCounters, ExpandedFlowSample, ExtendedAcl, ExtendedEgressQueue,
    ExtendedFunction, ExtendedGateway, ExtendedRouter, ExtendedSwitch, ExtendedUrl, ExtendedUser,
    FlowRecord, FlowRecordType, FlowSample, FlowType, HeaderProtocol, IfCounters, Processor,
    RecordHeader, SFlowV5, Sample, SampleHeader, SampledEthernet, SampledHeader, SampledIpv4,
    SampledIpv6, TokenringCounters, UrlDirection, VgCounters, VlanCounters,
};

pub const SFLOW_DATAGRAM_VERSION: u32 = 5;

pub const IPV4: u32 = 1;
pub const IPV6: u32 = 2;

pub const MAX_HEADER_SIZE: u16 = 256;

pub struct SFlowV5Parser;

impl Default for SFlowV5Parser {
    fn default() -> Self {
        SFlowV5Parser
    }
}

impl SFlowV5Parser {
    pub fn parse<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<SFlowV5, nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>> {
        parse_sflow_v5(input).map(|(_, packet)| packet)
    }

    pub fn parse_data_records<'a>(
        &'a mut self,
        input: &'a [u8],
    ) -> Result<Vec<FxHashMap<&'a str, DataValue>>, nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>>
    {
        let packet = parse_sflow_v5(input).map(|(_, packet)| packet)?;

        let mut records = Vec::with_capacity(16);

        packet.samples.iter().for_each(|sample| match sample {
            Sample::Flow(flow_sample) => {
                flow_sample
                    .records
                    .iter()
                    .for_each(|record| match &record.data {
                        FlowRecordType::SampledHeader(flow_record) => match flow_record.protocol {
                            HeaderProtocol::EthernetIso8023 => {
                                if let Ok(sliced) = SlicedPacket::from_ethernet(&flow_record.header)
                                {
                                    let (src_mac, dst_mac, etype) = match &sliced.link {
                                        Some(LinkSlice::Ethernet2(eth)) => {
                                            let header = eth.to_header();
                                            (
                                                MacAddr6::from(header.source),
                                                MacAddr6::from(header.destination),
                                                header.ether_type.0,
                                            )
                                        }
                                        _ => return,
                                    };

                                    match &sliced.net {
                                        Some(NetSlice::Ipv4(ipv4_slice)) => {
                                            let ipv4_header = ipv4_slice.header();
                                            let src_ip = Ipv4Addr::from(ipv4_header.source_addr());
                                            let dst_ip =
                                                Ipv4Addr::from(ipv4_header.destination_addr());
                                            let protocol = ipv4_header.protocol().0;

                                            match &sliced.transport {
                                                Some(TransportSlice::Tcp(tcp_slice)) => {
                                                    let src_port = tcp_slice.source_port();
                                                    let dst_port = tcp_slice.destination_port();

                                                    records.push(FxHashMap::from_iter([
                                                        (
                                                            "sampling_rate",
                                                            DataValue::U32(
                                                                flow_sample.sampling_rate,
                                                            ),
                                                        ),
                                                        (
                                                            "bytes",
                                                            DataValue::U32(
                                                                flow_record.frame_length,
                                                            ),
                                                        ),
                                                        ("packets", DataValue::U32(1)),
                                                        ("protocol", DataValue::U8(protocol)),
                                                        ("etype", DataValue::U16(etype)),
                                                        ("src_mac", DataValue::MacAddr(src_mac)),
                                                        ("dst_mac", DataValue::MacAddr(dst_mac)),
                                                        ("src_ip", DataValue::Ipv4(src_ip)),
                                                        ("dst_ip", DataValue::Ipv4(dst_ip)),
                                                        ("src_port", DataValue::U16(src_port)),
                                                        ("dst_port", DataValue::U16(dst_port)),
                                                    ]));
                                                }
                                                Some(TransportSlice::Udp(udp_slice)) => {
                                                    let src_port = udp_slice.source_port();
                                                    let dst_port = udp_slice.destination_port();

                                                    records.push(FxHashMap::from_iter([
                                                        (
                                                            "sampling_rate",
                                                            DataValue::U32(
                                                                flow_sample.sampling_rate,
                                                            ),
                                                        ),
                                                        (
                                                            "bytes",
                                                            DataValue::U32(
                                                                flow_record.frame_length,
                                                            ),
                                                        ),
                                                        ("packets", DataValue::U32(1)),
                                                        ("protocol", DataValue::U8(protocol)),
                                                        ("etype", DataValue::U16(etype)),
                                                        ("src_mac", DataValue::MacAddr(src_mac)),
                                                        ("dst_mac", DataValue::MacAddr(dst_mac)),
                                                        ("src_ip", DataValue::Ipv4(src_ip)),
                                                        ("dst_ip", DataValue::Ipv4(dst_ip)),
                                                        ("src_port", DataValue::U16(src_port)),
                                                        ("dst_port", DataValue::U16(dst_port)),
                                                    ]));
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            HeaderProtocol::Iso88024TokenBus => {}
                            HeaderProtocol::Iso88025TokenRing => {}
                            HeaderProtocol::Fddi => {}
                            HeaderProtocol::FrameRelay => {}
                            HeaderProtocol::X25 => {}
                            HeaderProtocol::Ppp => {}
                            HeaderProtocol::Smds => {}
                            HeaderProtocol::Aal5 => {}
                            HeaderProtocol::Aal5Ip => {}
                            HeaderProtocol::Ipv4 => {}
                            HeaderProtocol::Ipv6 => {}
                            HeaderProtocol::Mpls => {}
                            HeaderProtocol::Pos => {},
                        },
                        FlowRecordType::SampledEthernet(sampled_ethernet) => {}
                        FlowRecordType::SampledIpv4(flow_record) => {
                            let src_ip = flow_record.src_ip;
                            let dst_ip = flow_record.dst_ip;
                            let src_port = flow_record.src_port;
                            let dst_port = flow_record.dst_port;

                            records.push(FxHashMap::from_iter([
                                ("sampling_rate", DataValue::U32(flow_sample.sampling_rate)),
                                ("bytes", DataValue::U32(flow_record.length)),
                                ("packets", DataValue::U32(1)),
                                ("protocol", DataValue::U32(flow_record.protocol)),
                                ("etype", DataValue::U16(0x800)),
                                ("src_ip", DataValue::Ipv4(src_ip)),
                                ("dst_ip", DataValue::Ipv4(dst_ip)),
                                ("src_port", DataValue::U32(src_port)),
                                ("dst_port", DataValue::U32(dst_port)),
                            ]));
                        }
                        FlowRecordType::SampledIpv6(flow_record) => {
                            let src_ip = flow_record.src_ip;
                            let dst_ip = flow_record.dst_ip;
                            let src_port = flow_record.src_port;
                            let dst_port = flow_record.dst_port;

                            records.push(FxHashMap::from_iter([
                                ("sampling_rate", DataValue::U32(flow_sample.sampling_rate)),
                                ("bytes", DataValue::U32(flow_record.length)),
                                ("packets", DataValue::U32(1)),
                                ("protocol", DataValue::U32(flow_record.protocol)),
                                ("etype", DataValue::U16(0x86dd)),
                                ("src_ip", DataValue::Ipv6(src_ip)),
                                ("dst_ip", DataValue::Ipv6(dst_ip)),
                                ("src_port", DataValue::U32(src_port)),
                                ("dst_port", DataValue::U32(dst_port)),
                            ]));
                        }
                        FlowRecordType::ExtendedSwitch(extended_switch) => {}
                        FlowRecordType::ExtendedRouter(extended_router) => {}
                        FlowRecordType::ExtendedGateway(extended_gateway) => {}
                        FlowRecordType::ExtendedUser(extended_user) => {}
                        FlowRecordType::ExtendedUrl(extended_url) => {}
                        FlowRecordType::ExtendedEgressQueue(extended_egress_queue) => {}
                        FlowRecordType::ExtendedAcl(extended_acl) => {}
                        FlowRecordType::ExtendedFunction(extended_function) => {}
                        FlowRecordType::Unknown(items) => {}
                    });
            }
            Sample::Counter(counter_sample) => {}
            Sample::ExpandedFlow(expanded_flow_sample) => {}
            Sample::Drop(drop_sample) => {}
            Sample::Unknown(items) => {}
        });

        Ok(records)
    }
}

fn parse_sflow_v5(input: &[u8]) -> IResult<&[u8], SFlowV5> {
    let (input, version) = verify(be_u32, |i| *i == SFLOW_DATAGRAM_VERSION).parse(input)?;
    let (input, agent_address_type) = be_u32(input)?;

    let (input, agent_address) = match agent_address_type {
        IPV4 => {
            let (input, addr) = be_u32(input)?;
            (input, IpAddr::V4(Ipv4Addr::from(addr)))
        }
        IPV6 => {
            let (input, addr) = be_u128(input)?;
            (input, IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => fail().parse(input)?,
    };

    let (input, sub_agent_id) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, uptime) = be_u32(input)?;
    let (input, sample_count) = be_u32(input)?;

    let (input, samples) = many(sample_count as usize, |v| {
        let (input, data_format) = peek(be_u32).parse(v)?;

        match data_format {
            // SAMPLE_FORMAT_FLOW
            1 => {
                let (input, v) = parse_flow_sample(v)?;
                Ok((input, Sample::Flow(v)))
            }
            // SAMPLE_FORMAT_COUNTER
            2 => {
                let (input, v) = parse_counter_sample(v)?;
                Ok((input, Sample::Counter(v)))
            }
            // SAMPLE_FORMAT_EXPANDED_FLOW
            3 => {
                let (input, v) = parse_expanded_flow_sample(v)?;
                Ok((input, Sample::ExpandedFlow(v)))
            }
            // SAMPLE_FORMAT_EXPANDED_COUNTER - 4
            // SAMPLE_FORMAT_DROP - 5
            _ => {
                let (input, header) = parse_sample_header(input)?;
                let (input, data) = take(header.length as usize)(input)?;
                Ok((input, Sample::Unknown(data.to_vec())))
            }
        }
    })
    .parse(input)?;

    Ok((
        input,
        SFlowV5 {
            version,
            agent_address,
            sub_agent_id,
            sequence_number,
            uptime,
            samples,
        },
    ))
}

fn parse_sample_header(input: &[u8]) -> IResult<&[u8], SampleHeader> {
    let (input, format) = be_u32(input)?;
    let (input, length) = be_u32(input)?;
    let (input, sample_sequence_number) = be_u32(input)?;

    let (input, (source_id_type, source_id_value)) = match format {
        // SAMPLE_FORMAT_FLOW, SAMPLE_FORMAT_COUNTER
        1 | 2 => {
            let (input, source_id) = be_u32(input)?;

            let source_id_type = source_id >> 24;
            let source_id_value = source_id & 0x00ffffff;

            (input, (source_id_type, source_id_value))
        }
        // SAMPLE_FORMAT_EXPANDED_FLOW, SAMPLE_FORMAT_EXPANDED_COUNTER, SAMPLE_FORMAT_DROP
        3 | 4 | 5 => {
            let (input, source_id_type) = be_u32(input)?;
            let (input, source_id_value) = be_u32(input)?;

            (input, (source_id_type, source_id_value))
        }
        _ => fail().parse(input)?,
    };

    Ok((
        input,
        SampleHeader {
            format,
            length,
            sample_sequence_number,
            source_id_type,
            source_id_value,
        },
    ))
}

fn parse_flow_sample(input: &[u8]) -> IResult<&[u8], FlowSample> {
    let (input, header) = parse_sample_header(input)?;
    let (input, sampling_rate) = be_u32(input)?;
    let (input, sample_pool) = be_u32(input)?;
    let (input, drops) = be_u32(input)?;
    let (input, input_) = be_u32(input)?;
    let (input, output) = be_u32(input)?;
    let (input, flow_records_count) = be_u32(input)?;
    let (input, records) = many(flow_records_count as usize, parse_flow_record).parse(input)?;

    Ok((
        input,
        FlowSample {
            header,
            sampling_rate,
            sample_pool,
            drops,
            input: input_,
            output,
            records,
        },
    ))
}

fn parse_counter_sample(input: &[u8]) -> IResult<&[u8], CounterSample> {
    let (input, header) = parse_sample_header(input)?;
    let (input, records_count) = be_u32(input)?;
    let (input, records) = many(records_count as usize, parse_counter_record).parse(input)?;

    Ok((input, CounterSample { header, records }))
}

fn parse_expanded_flow_sample(input: &[u8]) -> IResult<&[u8], ExpandedFlowSample> {
    let (input, header) = parse_sample_header(input)?;
    let (input, sampling_rate) = be_u32(input)?;
    let (input, sample_pool) = be_u32(input)?;
    let (input, drops) = be_u32(input)?;
    let (input, input_if_format) = be_u32(input)?;
    let (input, input_if_value) = be_u32(input)?;
    let (input, output_if_format) = be_u32(input)?;
    let (input, output_if_value) = be_u32(input)?;
    let (input, flow_records_count) = be_u32(input)?;
    let (input, records) = many(flow_records_count as usize, parse_flow_record).parse(input)?;

    Ok((
        input,
        ExpandedFlowSample {
            header,
            sampling_rate,
            sample_pool,
            drops,
            input_if_format,
            input_if_value,
            output_if_format,
            output_if_value,
            records,
        },
    ))
}

fn parse_record_header(input: &[u8]) -> IResult<&[u8], RecordHeader> {
    let (input, data_format) = be_u32(input)?;
    let (input, length) = be_u32(input)?;

    Ok((
        input,
        RecordHeader {
            data_format,
            length,
        },
    ))
}

impl TryFrom<u32> for FlowType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(FlowType::SampledHeader),
            2 => Ok(FlowType::SampledEthernet),
            3 => Ok(FlowType::SampledIpv4),
            4 => Ok(FlowType::SampledIpv6),
            1001 => Ok(FlowType::ExtendedSwitch),
            1002 => Ok(FlowType::ExtendedRouter),
            1003 => Ok(FlowType::ExtendedGateway),
            1004 => Ok(FlowType::ExtendedUser),
            1005 => Ok(FlowType::ExtendedUrl),
            1036 => Ok(FlowType::ExtendedEgressQueue),
            1037 => Ok(FlowType::ExtendedAcl),
            1038 => Ok(FlowType::ExtendedFunction),
            _ => Err(value),
        }
    }
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data) = map(take(header.length as usize), |v| {
        match FlowType::try_from(header.data_format) {
            Ok(FlowType::SampledHeader) => {
                let (input, v) = parse_sampled_header(v)?;
                Ok(FlowRecordType::SampledHeader(v))
            }
            Ok(FlowType::SampledEthernet) => {
                let (input, v) = parse_sampled_ethernet(v)?;
                Ok(FlowRecordType::SampledEthernet(v))
            }
            Ok(FlowType::SampledIpv4) => {
                let (input, v) = parse_sampled_ipv4(v)?;
                Ok(FlowRecordType::SampledIpv4(v))
            }
            Ok(FlowType::SampledIpv6) => {
                let (input, v) = parse_sampled_ipv6(v)?;
                Ok(FlowRecordType::SampledIpv6(v))
            }
            Ok(FlowType::ExtendedSwitch) => {
                let (input, v) = parse_extended_switch(v)?;
                Ok(FlowRecordType::ExtendedSwitch(v))
            }
            Ok(FlowType::ExtendedRouter) => {
                let (input, v) = parse_extended_router(v)?;
                Ok(FlowRecordType::ExtendedRouter(v))
            }
            Ok(FlowType::ExtendedGateway) => {
                let (input, v) = parse_extended_gateway(v)?;
                Ok(FlowRecordType::ExtendedGateway(v))
            }
            Ok(FlowType::ExtendedUser) => {
                let (input, v) = parse_extended_user(v)?;
                Ok(FlowRecordType::ExtendedUser(v))
            }
            Ok(FlowType::ExtendedUrl) => {
                let (input, v) = parse_extended_url(v)?;
                Ok(FlowRecordType::ExtendedUrl(v))
            }
            Ok(FlowType::ExtendedEgressQueue) => {
                let (input, v) = parse_extended_egress_queue(v)?;
                Ok(FlowRecordType::ExtendedEgressQueue(v))
            }
            Ok(FlowType::ExtendedAcl) => {
                let (input, v) = parse_extended_acl(v)?;
                Ok(FlowRecordType::ExtendedAcl(v))
            }
            Ok(FlowType::ExtendedFunction) => {
                let (input, v) = parse_extended_function(v)?;
                Ok(FlowRecordType::ExtendedFunction(v))
            }
            Err(_) => Ok(FlowRecordType::Unknown(v.to_vec())),
        }
    })
    .parse(input)?;

    Ok((
        input,
        FlowRecord {
            header,
            data: data?,
        },
    ))
}

impl TryFrom<u32> for CounterType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CounterType::IfCounters),
            2 => Ok(CounterType::EthernetCounters),
            3 => Ok(CounterType::TokenringCounters),
            4 => Ok(CounterType::VgCounters),
            5 => Ok(CounterType::VlanCounters),
            1001 => Ok(CounterType::Processor),
            _ => Err(value),
        }
    }
}

fn parse_counter_record(input: &[u8]) -> IResult<&[u8], CounterRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data_length) = be_u32(input)?;
    let (input, data) = take(data_length as usize)(input)?;

    let (_, records) = many1(|v| match CounterType::try_from(header.data_format) {
        Ok(CounterType::IfCounters) => {
            let (input, v) = parse_if_counters(v)?;
            Ok((input, CounterRecordType::IfCounters(v)))
        }
        Ok(CounterType::EthernetCounters) => {
            let (input, v) = parse_ethernet_counters(v)?;
            Ok((input, CounterRecordType::EthernetCounters(v)))
        }
        Ok(CounterType::TokenringCounters) => {
            let (input, v) = parse_tokenring_counters(v)?;
            Ok((input, CounterRecordType::TokenringCounters(v)))
        }
        Ok(CounterType::VgCounters) => {
            let (input, v) = parse_vg_counters(v)?;
            Ok((input, CounterRecordType::VgCounters(v)))
        }
        Ok(CounterType::VlanCounters) => {
            let (input, v) = parse_vlan_counters(v)?;
            Ok((input, CounterRecordType::VlanCounters(v)))
        }
        Ok(CounterType::Processor) => {
            let (input, v) = parse_processor(v)?;
            Ok((input, CounterRecordType::Processor(v)))
        }
        Err(_) => {
            let (input, data) = take(data_length as usize)(v)?;
            Ok((input, CounterRecordType::Unknown(data.to_vec())))
        }
    })
    .parse(data)?;

    Ok((
        input,
        CounterRecord {
            header,
            data: records.into_iter().collect(),
        },
    ))
}

impl TryFrom<u32> for HeaderProtocol {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HeaderProtocol::EthernetIso8023),
            2 => Ok(HeaderProtocol::Iso88024TokenBus),
            3 => Ok(HeaderProtocol::Iso88025TokenRing),
            4 => Ok(HeaderProtocol::Fddi),
            5 => Ok(HeaderProtocol::FrameRelay),
            6 => Ok(HeaderProtocol::X25),
            7 => Ok(HeaderProtocol::Ppp),
            8 => Ok(HeaderProtocol::Smds),
            9 => Ok(HeaderProtocol::Aal5),
            10 => Ok(HeaderProtocol::Aal5Ip),
            11 => Ok(HeaderProtocol::Ipv4),
            12 => Ok(HeaderProtocol::Ipv6),
            13 => Ok(HeaderProtocol::Mpls),
            _ => Err(value),
        }
    }
}

fn parse_sampled_header(input: &[u8]) -> IResult<&[u8], SampledHeader> {
    let (input, protocol) = map_res(be_u32, |v| v.try_into()).parse(input)?;
    let (input, frame_length) = be_u32(input)?;
    let (input, stripped) = be_u32(input)?;
    let (input, original_length) = be_u32(input)?;
    let (input, header) = take(original_length as usize)(input)?;

    Ok((
        input,
        SampledHeader {
            protocol,
            frame_length,
            stripped,
            header: header.to_vec(),
        },
    ))
}

fn parse_sampled_ethernet(input: &[u8]) -> IResult<&[u8], SampledEthernet> {
    let (input, legnth) = be_u32(input)?;
    let (input, src_mac) = parse_mac_addr(input)?;
    let (input, dst_mac) = parse_mac_addr(input)?;
    let (input, type_) = be_u32(input)?;

    Ok((
        input,
        SampledEthernet {
            length: legnth,
            src_mac,
            dst_mac,
            r#type: type_,
        },
    ))
}

fn parse_sampled_ipv4(input: &[u8]) -> IResult<&[u8], SampledIpv4> {
    let (input, length) = be_u32(input)?;
    let (input, protocol) = be_u32(input)?;
    let (input, src_ip) = map(be_u32, |i| Ipv4Addr::from(i)).parse(input)?;
    let (input, dst_ip) = map(be_u32, |i| Ipv4Addr::from(i)).parse(input)?;
    let (input, src_port) = be_u32(input)?;
    let (input, dst_port) = be_u32(input)?;
    let (input, tcp_flags) = be_u32(input)?;
    let (input, tos) = be_u32(input)?;

    Ok((
        input,
        SampledIpv4 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            tos,
        },
    ))
}

fn parse_sampled_ipv6(input: &[u8]) -> IResult<&[u8], SampledIpv6> {
    let (input, length) = be_u32(input)?;
    let (input, protocol) = be_u32(input)?;
    let (input, src_ip) = map(be_u128, |i| Ipv6Addr::from(i)).parse(input)?;
    let (input, dst_ip) = map(be_u128, |i| Ipv6Addr::from(i)).parse(input)?;
    let (input, src_port) = be_u32(input)?;
    let (input, dst_port) = be_u32(input)?;
    let (input, tcp_flags) = be_u32(input)?;
    let (input, priority) = be_u32(input)?;

    Ok((
        input,
        SampledIpv6 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            priority,
        },
    ))
}

fn parse_extended_switch(input: &[u8]) -> IResult<&[u8], ExtendedSwitch> {
    let (input, src_vlan) = be_u32(input)?;
    let (input, src_priority) = be_u32(input)?;
    let (input, dst_vlan) = be_u32(input)?;
    let (input, dst_priority) = be_u32(input)?;

    Ok((
        input,
        ExtendedSwitch {
            src_vlan,
            src_priority,
            dst_vlan,
            dst_priority,
        },
    ))
}

fn parse_extended_router(input: &[u8]) -> IResult<&[u8], ExtendedRouter> {
    let (input, nexthop_ip_version) = be_u32(input)?;
    let (input, nexthop) = match nexthop_ip_version {
        IPV4 => {
            let (input, addr) = be_u32(input)?;
            (input, IpAddr::V4(Ipv4Addr::from(addr)))
        }
        IPV6 => {
            let (input, addr) = be_u128(input)?;
            (input, IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => fail().parse(input)?,
    };
    let (input, src_mask) = be_u32(input)?;
    let (input, dst_mask) = be_u32(input)?;

    Ok((
        input,
        ExtendedRouter {
            nexthop,
            src_mask,
            dst_mask,
        },
    ))
}

impl TryFrom<u32> for AsPathSegmentType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsPathSegmentType::AsSet),
            2 => Ok(AsPathSegmentType::AsSequence),
            _ => Err(value),
        }
    }
}

fn parse_extended_gateway(input: &[u8]) -> IResult<&[u8], ExtendedGateway> {
    let (input, as_) = be_u32(input)?;
    let (input, src_as) = be_u32(input)?;
    let (input, src_peer_as) = be_u32(input)?;

    let (input, dst_as_path_type) = map_res(be_u32, |v| v.try_into()).parse(input)?;
    let (input, dst_as_path_length) = be_u32(input)?;

    let (input, dst_as_path) =
        map(
            many(dst_as_path_length as usize, be_u32),
            |v: Vec<u32>| match dst_as_path_type {
                AsPathSegmentType::AsSet => AsPathType::AsSet(v.into_iter().collect()),
                AsPathSegmentType::AsSequence => AsPathType::AsSequence(v.into_iter().collect()),
            },
        )
        .parse(input)?;

    let (input, communities_length) = be_u32(input)?;
    let (input, communities) = many(communities_length as usize, be_u32).parse(input)?;

    let (input, localpref) = be_u32(input)?;

    Ok((
        input,
        ExtendedGateway {
            r#as: as_,
            src_as,
            src_peer_as,
            dst_as_path,
            communities,
            localpref,
        },
    ))
}

fn parse_extended_user(input: &[u8]) -> IResult<&[u8], ExtendedUser> {
    let (input, src_user) = parse_string(input)?;
    let (input, dst_user) = parse_string(input)?;

    Ok((input, ExtendedUser { src_user, dst_user }))
}

impl TryFrom<u32> for UrlDirection {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(UrlDirection::Src),
            2 => Ok(UrlDirection::Dst),
            _ => Err(value),
        }
    }
}

fn parse_extended_url(input: &[u8]) -> IResult<&[u8], ExtendedUrl> {
    let (input, direction) = map_res(be_u32, |v| v.try_into()).parse(input)?;
    let (input, url) = parse_string(input)?;

    Ok((input, ExtendedUrl { direction, url }))
}

fn parse_extended_egress_queue(input: &[u8]) -> IResult<&[u8], ExtendedEgressQueue> {
    let (input, queue) = be_u32(input)?;

    Ok((input, ExtendedEgressQueue { queue }))
}

impl TryFrom<u32> for Direction {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Direction::Unknown),
            1 => Ok(Direction::Ingress),
            2 => Ok(Direction::Egress),
            _ => Err(value),
        }
    }
}

fn parse_extended_acl(input: &[u8]) -> IResult<&[u8], ExtendedAcl> {
    let (input, number) = be_u32(input)?;
    let (input, name) = parse_string(input)?;
    let (input, direction) = map_res(be_u32, |v| v.try_into()).parse(input)?;

    Ok((
        input,
        ExtendedAcl {
            number,
            name,
            direction,
        },
    ))
}

fn parse_extended_function(input: &[u8]) -> IResult<&[u8], ExtendedFunction> {
    let (input, symbol) = parse_string(input)?;

    Ok((input, ExtendedFunction { symbol }))
}

fn parse_if_counters(input: &[u8]) -> IResult<&[u8], IfCounters> {
    let (input, if_index) = be_u32(input)?;
    let (input, if_type) = be_u32(input)?;
    let (input, if_speed) = be_u64(input)?;
    let (input, if_direction) = be_u32(input)?;
    let (input, if_status) = be_u32(input)?;
    let (input, if_in_octets) = be_u64(input)?;
    let (input, if_in_ucast_pkts) = be_u32(input)?;
    let (input, if_in_multicast_pkts) = be_u32(input)?;
    let (input, if_in_broadcast_pkts) = be_u32(input)?;
    let (input, if_in_discards) = be_u32(input)?;
    let (input, if_in_errors) = be_u32(input)?;
    let (input, if_in_unknown_protos) = be_u32(input)?;
    let (input, if_out_octets) = be_u64(input)?;
    let (input, if_out_ucast_pkts) = be_u32(input)?;
    let (input, if_out_multicast_pkts) = be_u32(input)?;
    let (input, if_out_broadcast_pkts) = be_u32(input)?;
    let (input, if_out_discards) = be_u32(input)?;
    let (input, if_out_errors) = be_u32(input)?;
    let (input, if_promiscuous_mode) = be_u32(input)?;

    Ok((
        input,
        IfCounters {
            if_index,
            if_type,
            if_speed,
            if_direction,
            if_status,
            if_in_octets,
            if_in_ucast_pkts,
            if_in_multicast_pkts,
            if_in_broadcast_pkts,
            if_in_discards,
            if_in_errors,
            if_in_unknown_protos,
            if_out_octets,
            if_out_ucast_pkts,
            if_out_multicast_pkts,
            if_out_broadcast_pkts,
            if_out_discards,
            if_out_errors,
            if_promiscuous_mode,
        },
    ))
}

fn parse_ethernet_counters(input: &[u8]) -> IResult<&[u8], EthernetCounters> {
    let (input, dot3_stats_alignment_errors) = be_u32(input)?;
    let (input, dot3_stats_fcs_errors) = be_u32(input)?;
    let (input, dot3_stats_single_collision_frames) = be_u32(input)?;
    let (input, dot3_stats_multiple_collision_frames) = be_u32(input)?;
    let (input, dot3_stats_sqetest_errors) = be_u32(input)?;
    let (input, dot3_stats_deferred_transmissions) = be_u32(input)?;
    let (input, dot3_stats_late_collisions) = be_u32(input)?;
    let (input, dot3_stats_excessive_collisions) = be_u32(input)?;
    let (input, dot3_stats_internal_mac_transmit_errors) = be_u32(input)?;
    let (input, dot3_stats_carrier_sense_errors) = be_u32(input)?;
    let (input, dot3_stats_frame_too_longs) = be_u32(input)?;
    let (input, dot3_stats_internal_mac_receive_errors) = be_u32(input)?;
    let (input, dot3_stats_symbol_errors) = be_u32(input)?;

    Ok((
        input,
        EthernetCounters {
            dot3_stats_alignment_errors,
            dot3_stats_fcs_errors,
            dot3_stats_single_collision_frames,
            dot3_stats_multiple_collision_frames,
            dot3_stats_sqetest_errors,
            dot3_stats_deferred_transmissions,
            dot3_stats_late_collisions,
            dot3_stats_excessive_collisions,
            dot3_stats_internal_mac_transmit_errors,
            dot3_stats_carrier_sense_errors,
            dot3_stats_frame_too_longs,
            dot3_stats_internal_mac_receive_errors,
            dot3_stats_symbol_errors,
        },
    ))
}

fn parse_tokenring_counters(input: &[u8]) -> IResult<&[u8], TokenringCounters> {
    let (input, dot5_stats_line_errors) = be_u32(input)?;
    let (input, dot5_stats_burst_errors) = be_u32(input)?;
    let (input, dot5_stats_ac_errors) = be_u32(input)?;
    let (input, dot5_stats_abort_trans_errors) = be_u32(input)?;
    let (input, dot5_stats_internal_errors) = be_u32(input)?;
    let (input, dot5_stats_lost_frame_errors) = be_u32(input)?;
    let (input, dot5_stats_receive_congestions) = be_u32(input)?;
    let (input, dot5_stats_frame_copied_errors) = be_u32(input)?;
    let (input, dot5_stats_token_errors) = be_u32(input)?;
    let (input, dot5_stats_soft_errors) = be_u32(input)?;
    let (input, dot5_stats_hard_errors) = be_u32(input)?;
    let (input, dot5_stats_signal_loss) = be_u32(input)?;
    let (input, dot5_stats_transmit_beacons) = be_u32(input)?;
    let (input, dot5_stats_recoveries) = be_u32(input)?;
    let (input, dot5_stats_lobe_wires) = be_u32(input)?;
    let (input, dot5_stats_removes) = be_u32(input)?;
    let (input, dot5_stats_singles) = be_u32(input)?;
    let (input, dot5_stats_freq_errors) = be_u32(input)?;

    Ok((
        input,
        TokenringCounters {
            dot5_stats_line_errors,
            dot5_stats_burst_errors,
            dot5_stats_ac_errors,
            dot5_stats_abort_trans_errors,
            dot5_stats_internal_errors,
            dot5_stats_lost_frame_errors,
            dot5_stats_receive_congestions,
            dot5_stats_frame_copied_errors,
            dot5_stats_token_errors,
            dot5_stats_soft_errors,
            dot5_stats_hard_errors,
            dot5_stats_signal_loss,
            dot5_stats_transmit_beacons,
            dot5_stats_recoveries,
            dot5_stats_lobe_wires,
            dot5_stats_removes,
            dot5_stats_singles,
            dot5_stats_freq_errors,
        },
    ))
}

fn parse_vg_counters(input: &[u8]) -> IResult<&[u8], VgCounters> {
    let (input, dot12_in_high_priority_frames) = be_u32(input)?;
    let (input, dot12_in_high_priority_octets) = be_u64(input)?;
    let (input, dot12_in_norm_priority_frames) = be_u32(input)?;
    let (input, dot12_in_norm_priority_octets) = be_u64(input)?;
    let (input, dot12_in_ipm_errors) = be_u32(input)?;
    let (input, dot12_in_oversize_frame_errors) = be_u32(input)?;
    let (input, dot12_in_data_errors) = be_u32(input)?;
    let (input, dot12_in_null_addressed_frames) = be_u32(input)?;
    let (input, dot12_out_high_priority_frames) = be_u32(input)?;
    let (input, dot12_out_high_priority_octets) = be_u64(input)?;
    let (input, dot12_transition_into_training) = be_u32(input)?;
    let (input, dot12_hc_in_high_priority_octets) = be_u64(input)?;
    let (input, dot12_hc_in_norm_priority_octets) = be_u64(input)?;
    let (input, dot12_hc_out_high_priority_octets) = be_u64(input)?;

    Ok((
        input,
        VgCounters {
            dot12_in_high_priority_frames,
            dot12_in_high_priority_octets,
            dot12_in_norm_priority_frames,
            dot12_in_norm_priority_octets,
            dot12_in_ipm_errors,
            dot12_in_oversize_frame_errors,
            dot12_in_data_errors,
            dot12_in_null_addressed_frames,
            dot12_out_high_priority_frames,
            dot12_out_high_priority_octets,
            dot12_transition_into_training,
            dot12_hc_in_high_priority_octets,
            dot12_hc_in_norm_priority_octets,
            dot12_hc_out_high_priority_octets,
        },
    ))
}

fn parse_vlan_counters(input: &[u8]) -> IResult<&[u8], VlanCounters> {
    let (input, vlan_id) = be_u32(input)?;
    let (input, octets) = be_u64(input)?;
    let (input, ucast_pkts) = be_u32(input)?;
    let (input, multicast_pkts) = be_u32(input)?;
    let (input, broadcast_pkts) = be_u32(input)?;
    let (input, discards) = be_u32(input)?;

    Ok((
        input,
        VlanCounters {
            vlan_id,
            octets,
            ucast_pkts,
            multicast_pkts,
            broadcast_pkts,
            discards,
        },
    ))
}

fn parse_processor(input: &[u8]) -> IResult<&[u8], Processor> {
    let (input, avg_5s_cpu) = be_i32(input)?;
    let (input, avg_1m_cpu) = be_i32(input)?;
    let (input, avg_5m_cpu) = be_i32(input)?;
    let (input, total_memory) = be_u64(input)?;
    let (input, free_memory) = be_u64(input)?;

    Ok((
        input,
        Processor {
            avg_5s_cpu,
            avg_1m_cpu,
            avg_5m_cpu,
            total_memory,
            free_memory,
        },
    ))
}

fn parse_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = be_u32(input)?;
    let (input, string) = map(take(length as usize), |v| {
        String::from_utf8_lossy(v).to_string()
    })
    .parse(input)?;

    Ok((input, string))
}

fn parse_mac_addr(input: &[u8]) -> IResult<&[u8], MacAddr6> {
    map(take(6usize), |i: &[u8]| {
        MacAddr6::new(i[0], i[1], i[2], i[3], i[4], i[5])
    })
    .parse(input)
}
