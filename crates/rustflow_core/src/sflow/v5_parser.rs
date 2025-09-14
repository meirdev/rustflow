use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{fail, map, peek, verify};
use nom::error::Error;
use nom::multi::{many, many1};
use nom::number::complete::{be_i32, be_u32, be_u64, be_u128};
use nom::{IResult, Parser};
use pnet_base::MacAddr;
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use rustc_hash::FxHashMap;

pub const SFLOW_DATAGRAM_VERSION: u32 = 5;

pub const IPV4: u32 = 1;
pub const IPV6: u32 = 2;

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
                                EthernetPacket::new(&flow_record.header).map(|eth_packet| {
                                    let src_mac = eth_packet.get_source();
                                    let dst_mac = eth_packet.get_destination();

                                    match eth_packet.get_ethertype() {
                                        EtherTypes::Ipv4 => {
                                            let ipv4_packet =
                                                Ipv4Packet::new(&eth_packet.payload());

                                            if let Some(ipv4_packet) = ipv4_packet {
                                                match ipv4_packet.get_next_level_protocol() {
                                                IpNextHeaderProtocols::Tcp => {
                                                    if let Some(tcp_packet) =
                                                        TcpPacket::new(&ipv4_packet.payload())
                                                    {
                                                        let src_ip = ipv4_packet.get_source();
                                                        let dst_ip = ipv4_packet.get_destination();
                                                        let src_port = tcp_packet.get_source();
                                                        let dst_port = tcp_packet.get_destination();

                                                        records.push(FxHashMap::from_iter([
                                                            ("sampling_rate", DataValue::U32(flow_sample.sampling_rate)),
                                                            ("bytes", DataValue::U32(flow_record.frame_length)),
                                                            ("packets", DataValue::U32(1)),
                                                            ("protocol", DataValue::U8(ipv4_packet.get_next_level_protocol().0)),
                                                            ("etype", DataValue::U16(eth_packet.get_ethertype().0)),
                                                            (
                                                                "src_mac",
                                                                DataValue::MacAddr(src_mac),
                                                            ),
                                                            (
                                                                "dst_mac",
                                                                DataValue::MacAddr(dst_mac),
                                                            ),
                                                            ("src_ip", DataValue::Ipv4(src_ip)),
                                                            ("dst_ip", DataValue::Ipv4(dst_ip)),
                                                            ("src_port", DataValue::U16(src_port)),
                                                            ("dst_port", DataValue::U16(dst_port)),
                                                        ]));
                                                    }
                                                }
                                                IpNextHeaderProtocols::Udp => {
                                                    if let Some(udp_packet) = UdpPacket::new(&ipv4_packet.payload()) {
                                                        let src_ip = ipv4_packet.get_source();
                                                        let dst_ip = ipv4_packet.get_destination();
                                                        let src_port = udp_packet.get_source();
                                                        let dst_port = udp_packet.get_destination();

                                                        records.push(FxHashMap::from_iter([
                                                            ("sampling_rate", DataValue::U32(flow_sample.sampling_rate)),
                                                            ("bytes", DataValue::U32(flow_record.frame_length)),
                                                            ("packets", DataValue::U32(1)),
                                                            ("protocol", DataValue::U8(ipv4_packet.get_next_level_protocol().0)),
                                                            ("etype", DataValue::U16(eth_packet.get_ethertype().0)),
                                                            (
                                                                "src_mac",
                                                                DataValue::MacAddr(src_mac),
                                                            ),
                                                            (
                                                                "dst_mac",
                                                                DataValue::MacAddr(dst_mac),
                                                            ),
                                                            ("src_ip", DataValue::Ipv4(src_ip)),
                                                            ("dst_ip", DataValue::Ipv4(dst_ip)),
                                                            ("src_port", DataValue::U16(src_port)),
                                                            ("dst_port", DataValue::U16(dst_port)),
                                                        ]));
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    _ => {}
                                }});
                            }
                            HeaderProtocol::Iso88024TokenBus => {},
                            HeaderProtocol::Iso88025TokenRing => {},
                            HeaderProtocol::Fddi => {},
                            HeaderProtocol::FrameRelay => {},
                            HeaderProtocol::X25 => {},
                            HeaderProtocol::Ppp => {},
                            HeaderProtocol::Smds => {},
                            HeaderProtocol::Aal5 => {},
                            HeaderProtocol::Aal5Ip => {},
                            HeaderProtocol::Ipv4 => {},
                            HeaderProtocol::Ipv6 => {},
                            HeaderProtocol::Mpls => {},
                        },
                        FlowRecordType::SampledEthernet(sampled_ethernet) => {},
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
                        },
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
                        },
                        FlowRecordType::ExtendedSwitch(extended_switch) => {},
                        FlowRecordType::ExtendedRouter(extended_router) => {},
                        FlowRecordType::ExtendedGateway(extended_gateway) => {},
                        FlowRecordType::ExtendedUser(extended_user) => {},
                        FlowRecordType::ExtendedUrl(extended_url) => {},
                        FlowRecordType::ExtendedEgressQueue(extended_egress_queue) => {},
                        FlowRecordType::ExtendedAcl(extended_acl) => {},
                        FlowRecordType::ExtendedFunction(extended_function) => {},
                        FlowRecordType::Unknown(items) => {},
                    });
            }
            Sample::Counter(counter_sample) => {},
            Sample::ExpandedFlow(expanded_flow_sample) => {},
            Sample::Drop(drop_sample) => {},
            Sample::Unknown(items) => {},
        });

        Ok(records)
    }
}

pub enum DataValue {
    Null,
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    MacAddr(MacAddr),
    U8(u8),
    U16(u16),
    U32(u32),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

/// Header information for sFlow version 5 datagrams.
#[derive(Debug, Clone)]
pub struct SFlowV5 {
    /// The version of the sFlow datagram.
    pub version: u32,
    /// IP address of sampling agent, sFlowAgentAddress.
    pub agent_address: IpAddr,
    /// Used to distinguishing between datagram streams from separate agent sub
    /// entities within an device.
    pub sub_agent_id: u32,
    /// Incremented with each sample datagram generated by a sub-agent within an
    /// agent.
    pub sequence_number: u32,
    /// Current time (in milliseconds since device last booted).
    pub uptime: u32,
    /// An array of sample records.
    pub samples: Vec<Sample>,
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

#[derive(Debug, Clone)]
pub enum Sample {
    /// Flow sample.
    Flow(FlowSample),
    /// Counter sample.
    Counter(CounterSample),
    /// Expanded flow sample.
    ExpandedFlow(ExpandedFlowSample),
    /// Drop sample.
    Drop(DropSample),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum DataFormat {}

#[derive(Debug, Clone)]
pub struct SampleHeader {
    pub format: u32,
    pub length: u32,
    pub sample_sequence_number: u32,
    pub source_id_type: u32,
    pub source_id_value: u32,
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

#[derive(Debug, Clone)]
pub struct FlowSample {
    pub header: SampleHeader,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input: u32,
    pub output: u32,
    pub records: Vec<FlowRecord>,
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

#[derive(Debug, Clone)]
pub struct CounterSample {
    pub header: SampleHeader,
    pub records: Vec<CounterRecord>,
}

fn parse_counter_sample(input: &[u8]) -> IResult<&[u8], CounterSample> {
    let (input, header) = parse_sample_header(input)?;
    let (input, records_count) = be_u32(input)?;
    let (input, records) = many(records_count as usize, parse_counter_record).parse(input)?;

    Ok((input, CounterSample { header, records }))
}

#[derive(Debug, Clone)]
pub struct ExpandedFlowSample {
    pub header: SampleHeader,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input_if_format: u32,
    pub input_if_value: u32,
    pub output_if_format: u32,
    pub output_if_value: u32,
    pub records: Vec<FlowRecord>,
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

#[derive(Debug, Clone)]
pub struct DropSample {
    pub header: SampleHeader,
    pub drops: u32,
    pub input: u32,
    pub output: u32,
    pub reason: DropReason,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub data_format: u32,
    pub length: u32,
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

#[derive(Debug, Clone)]
pub enum FlowRecordType {
    SampledHeader(SampledHeader),
    SampledEthernet(SampledEthernet),
    SampledIpv4(SampledIpv4),
    SampledIpv6(SampledIpv6),
    ExtendedSwitch(ExtendedSwitch),
    ExtendedRouter(ExtendedRouter),
    ExtendedGateway(ExtendedGateway),
    ExtendedUser(ExtendedUser),
    ExtendedUrl(ExtendedUrl),
    ExtendedEgressQueue(ExtendedEgressQueue),
    ExtendedAcl(ExtendedAcl),
    ExtendedFunction(ExtendedFunction),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum FlowType {
    SampledHeader = 1,
    SampledEthernet = 2,
    SampledIpv4 = 3,
    SampledIpv6 = 4,
    ExtendedSwitch = 1001,
    ExtendedRouter = 1002,
    ExtendedGateway = 1003,
    ExtendedUser = 1004,
    ExtendedUrl = 1005,
    ExtendedEgressQueue = 1036,
    ExtendedAcl = 1037,
    ExtendedFunction = 1038,
    Unknown(u32),
}

impl From<u32> for FlowType {
    fn from(value: u32) -> Self {
        match value {
            1 => FlowType::SampledHeader,
            2 => FlowType::SampledEthernet,
            3 => FlowType::SampledIpv4,
            4 => FlowType::SampledIpv6,
            1001 => FlowType::ExtendedSwitch,
            1002 => FlowType::ExtendedRouter,
            1003 => FlowType::ExtendedGateway,
            1004 => FlowType::ExtendedUser,
            1005 => FlowType::ExtendedUrl,
            1036 => FlowType::ExtendedEgressQueue,
            1037 => FlowType::ExtendedAcl,
            1038 => FlowType::ExtendedFunction,
            _ => FlowType::Unknown(value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub header: RecordHeader,
    pub data: FlowRecordType,
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data) = map(take(header.length as usize), |v| {
        match FlowType::from(header.data_format) {
            FlowType::SampledHeader => {
                let (input, v) = parse_sampled_header(v)?;
                Ok(FlowRecordType::SampledHeader(v))
            }
            FlowType::SampledEthernet => {
                let (input, v) = parse_sampled_ethernet(v)?;
                Ok(FlowRecordType::SampledEthernet(v))
            }
            FlowType::SampledIpv4 => {
                let (input, v) = parse_sampled_ipv4(v)?;
                Ok(FlowRecordType::SampledIpv4(v))
            }
            FlowType::SampledIpv6 => {
                let (input, v) = parse_sampled_ipv6(v)?;
                Ok(FlowRecordType::SampledIpv6(v))
            }
            FlowType::ExtendedSwitch => {
                let (input, v) = parse_extended_switch(v)?;
                Ok(FlowRecordType::ExtendedSwitch(v))
            }
            FlowType::ExtendedRouter => {
                let (input, v) = parse_extended_router(v)?;
                Ok(FlowRecordType::ExtendedRouter(v))
            }
            FlowType::ExtendedGateway => {
                let (input, v) = parse_extended_gateway(v)?;
                Ok(FlowRecordType::ExtendedGateway(v))
            }
            FlowType::ExtendedUser => {
                let (input, v) = parse_extended_user(v)?;
                Ok(FlowRecordType::ExtendedUser(v))
            }
            FlowType::ExtendedUrl => {
                let (input, v) = parse_extended_url(v)?;
                Ok(FlowRecordType::ExtendedUrl(v))
            }
            FlowType::ExtendedEgressQueue => {
                let (input, v) = parse_extended_egress_queue(v)?;
                Ok(FlowRecordType::ExtendedEgressQueue(v))
            }
            FlowType::ExtendedAcl => {
                let (input, v) = parse_extended_acl(v)?;
                Ok(FlowRecordType::ExtendedAcl(v))
            }
            FlowType::ExtendedFunction => {
                let (input, v) = parse_extended_function(v)?;
                Ok(FlowRecordType::ExtendedFunction(v))
            }
            FlowType::Unknown(_) => {
                // If the data format is unknown, we just return the raw bytes.
                Ok(FlowRecordType::Unknown(v.to_vec()))
            }
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

#[derive(Debug, Clone)]
pub enum CounterRecordType {
    IfCounters(IfCounters),
    EthernetCounters(EthernetCounters),
    TokenringCounters(TokenringCounters),
    VgCounters(VgCounters),
    VlanCounters(VlanCounters),
    Processor(Processor),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum CounterType {
    IfCounters = 1,
    EthernetCounters = 2,
    TokenringCounters = 3,
    VgCounters = 4,
    VlanCounters = 5,
    Processor = 1001,
    Unknown(u32),
}

impl From<u32> for CounterType {
    fn from(value: u32) -> Self {
        match value {
            1 => CounterType::IfCounters,
            2 => CounterType::EthernetCounters,
            3 => CounterType::TokenringCounters,
            4 => CounterType::VgCounters,
            5 => CounterType::VlanCounters,
            1001 => CounterType::Processor,
            _ => CounterType::Unknown(value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CounterRecord {
    pub header: RecordHeader,
    pub data: Vec<CounterRecordType>,
}

fn parse_counter_record(input: &[u8]) -> IResult<&[u8], CounterRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data_length) = be_u32(input)?;
    let (input, data) = take(data_length as usize)(input)?;

    let (_, records) = many1(|v| match CounterType::from(header.data_format) {
        CounterType::IfCounters => {
            let (input, v) = parse_if_counters(v)?;
            Ok((input, CounterRecordType::IfCounters(v)))
        }
        CounterType::EthernetCounters => {
            let (input, v) = parse_ethernet_counters(v)?;
            Ok((input, CounterRecordType::EthernetCounters(v)))
        }
        CounterType::TokenringCounters => {
            let (input, v) = parse_tokenring_counters(v)?;
            Ok((input, CounterRecordType::TokenringCounters(v)))
        }
        CounterType::VgCounters => {
            let (input, v) = parse_vg_counters(v)?;
            Ok((input, CounterRecordType::VgCounters(v)))
        }
        CounterType::VlanCounters => {
            let (input, v) = parse_vlan_counters(v)?;
            Ok((input, CounterRecordType::VlanCounters(v)))
        }
        CounterType::Processor => {
            let (input, v) = parse_processor(v)?;
            Ok((input, CounterRecordType::Processor(v)))
        }
        CounterType::Unknown(_) => {
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

/// The maximum sampled header size.
pub const MAX_HEADER_SIZE: u16 = 256;

/// The header protocol describes the format of the sampled header.
#[derive(Debug, Clone)]
#[repr(u32)]
pub enum HeaderProtocol {
    EthernetIso8023 = 1,
    Iso88024TokenBus = 2,
    Iso88025TokenRing = 3,
    Fddi = 4,
    FrameRelay = 5,
    X25 = 6,
    Ppp = 7,
    Smds = 8,
    Aal5 = 9,
    Aal5Ip = 10, // e.g., Cisco AAL5 mux
    Ipv4 = 11,
    Ipv6 = 12,
    Mpls = 13,
}

impl From<u32> for HeaderProtocol {
    fn from(value: u32) -> Self {
        match value {
            1 => HeaderProtocol::EthernetIso8023,
            2 => HeaderProtocol::Iso88024TokenBus,
            3 => HeaderProtocol::Iso88025TokenRing,
            4 => HeaderProtocol::Fddi,
            5 => HeaderProtocol::FrameRelay,
            6 => HeaderProtocol::X25,
            7 => HeaderProtocol::Ppp,
            8 => HeaderProtocol::Smds,
            9 => HeaderProtocol::Aal5,
            10 => HeaderProtocol::Aal5Ip,
            11 => HeaderProtocol::Ipv4,
            12 => HeaderProtocol::Ipv6,
            13 => HeaderProtocol::Mpls,
            _ => panic!("Unknown header protocol"),
        }
    }
}

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum DropReason {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragNeeded = 4,
    SrcRouteFailed = 5,
    DstNetUnknown = 6, // ipv4_lpm_miss, ipv6_lpm_miss
    DstHostUnknown = 7,
    SrcHostIsolated = 8,
    DstNetProhibited = 9, // reject_route
    DstHostProhibited = 10,
    DstNetTosUnreachable = 11,
    DstHostTosUnreachable = 12,
    CommAdminProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
    Unknown = 256,
    TtlExceeded = 257,   // ttl_value_is_too_small
    Acl = 258,           // ingress_flow_action_drop, egress_flow_action_drop, group acl_drops
    NoBufferSpace = 259, // tail_drop
    Red = 260,           // early_drop
    TrafficShaping = 261,
    PktTooBig = 262, // mtu_value_is_too_small
    SrcMacIsMulticast = 263,
    VlanTagMismatch = 264,
    IngressVlanFilter = 265,
    IngressSpanningTreeFilter = 266,
    PortListIsEmpty = 267,
    PortLoopbackFilter = 268,
    BlackholeRoute = 269,
    NonIp = 270,
    UcDipOverMcDmac = 271,
    DipIsLoopbackAddress = 272,
    SipIsMc = 273,
    SipIsLoopbackAddress = 274,
    IpHeaderCorrupted = 275,
    Ipv4SipIsLimitedBc = 276,
    Ipv6McDipReservedScope = 277,
    Ipv6McDipInterfaceLocalScope = 278,
    UnresolvedNeigh = 279,
    McReversePathForwarding = 280,
    NonRoutablePacket = 281,
    DecapError = 282,
    OverlaySmacIsMc = 283,
    UnknownL2 = 284,          // group l2_drops
    UnknownL3 = 285,          // group l3_drops
    UnknownL3Exception = 286, // group l3_exceptions
    UnknownBuffer = 287,      // group buffer_drops
    UnknownTunnel = 288,      // group tunnel_drops
    UnknownL4 = 289,
    SipIsUnspecified = 290,
    MlagPortIsolated = 291,
    BlackholeArpNeigh = 292,
    SrcMacIsDmac = 293,
    DmacIsReserved = 294,
    SipIsClassE = 295,
    McDmacMismatch = 296,
    SipIsDip = 297,
    DipIsLocalNetwork = 298,
    DipIsLinkLocal = 299,
    OverlaySmacIsDmac = 300,
    EgressVlanFilter = 301,
    UcReversePathForwarding = 302,
    SplitHorizon = 303,
}

pub enum FlowData {
    SampledHeader = 1,
    SampledEthernet = 2,
    SampledIpv4 = 3,
    SampledIpv6 = 4,
    ExtendedSwitch = 1001,
    ExtendedRouter = 1002,
    ExtendedGateway = 1003,
    ExtendedUser = 1004,
    ExtendedUrl = 1005,
    ExtendedEgressQueue = 1036,
    ExtendedAcl = 1037,
    ExtendedFunction = 1038,
}

/// Raw Packet Header.
#[derive(Debug, Clone)]
pub struct SampledHeader {
    /// Format of sampled header.
    pub protocol: HeaderProtocol,
    /// Original length of packet before sampling.
    ///
    /// Note: For a layer 2 header_protocol, length is total number of octets of
    /// data received on the network (excluding framing bits but including FCS
    /// octets). Hardware limitations may prevent an exact reporting of the
    /// underlying frame length, but an agent should attempt to be as accurate
    /// as possible. Any octets added to the frame_length to compensate for
    /// encapsulations removed by the underlying hardware must also be added to
    /// the stripped count.
    pub frame_length: u32,
    /// The number of octets removed from the packet before extracting the
    /// header<> octets. Trailing encapsulation data corresponding to any
    /// leading encapsulations that were stripped must also be stripped.
    /// Trailing encapsulation data for the outermost protocol layer included in
    /// the sampled header must be stripped.
    ///
    /// In the case of a non-encapsulated 802.3 packet stripped >= 4 since VLAN
    /// taginformation might have been stripped off in addition to the FCS.
    ///
    /// Outer encapsulations that are ambiguous, or not one of the standard
    /// header_protocol must be stripped.
    pub stripped: u32,
    /// Header bytes.
    pub header: Vec<u8>,
}

fn parse_sampled_header(input: &[u8]) -> IResult<&[u8], SampledHeader> {
    let (input, protocol) = be_u32(input)?;
    let (input, frame_length) = be_u32(input)?;
    let (input, stripped) = be_u32(input)?;
    let (input, original_length) = be_u32(input)?;
    let (input, header) = take(original_length as usize)(input)?;

    Ok((
        input,
        SampledHeader {
            protocol: protocol.into(),
            frame_length,
            stripped,
            header: header.to_vec(),
        },
    ))
}

/// Ethernet Frame Data.
#[derive(Debug, Clone)]
pub struct SampledEthernet {
    /// The length of the MAC packet received on the network, excluding lower
    /// layer encapsulations and framing bits but including FCS octets.
    pub length: u32,
    /// Source MAC address.
    pub src_mac: MacAddr6,
    /// Destination MAC address.
    pub dst_mac: MacAddr6,
    /// Ethernet packet type.
    pub r#type: u32,
}

fn parse_sampled_ethernet(input: &[u8]) -> IResult<&[u8], SampledEthernet> {
    let (input, legnth) = be_u32(input)?;
    let (input, src_mac) = map(take(6usize), |i: &[u8]| {
        MacAddr6::new(i[0], i[1], i[2], i[3], i[4], i[5])
    })
    .parse(input)?;
    let (input, dst_mac) = map(take(6usize), |i: &[u8]| {
        MacAddr6::new(i[0], i[1], i[2], i[3], i[4], i[5])
    })
    .parse(input)?;
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

/// Packet IP version 4 data.
#[derive(Debug, Clone)]
pub struct SampledIpv4 {
    /// The length of the IP packet excluding lower layer encapsulations.
    pub length: u32,
    /// IP Protocol type (for example, TCP = 6, UDP = 17).
    pub protocol: u32,
    /// Source IP Address.
    pub src_ip: Ipv4Addr,
    /// Destination IP Address.
    pub dst_ip: Ipv4Addr,
    /// TCP/UDP source port number or equivalent.
    pub src_port: u32,
    /// TCP/UDP destination port number or equivalent.
    pub dst_port: u32,
    /// TCP flags.
    pub tcp_flags: u32,
    /// IP type of service.
    pub tos: u32,
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

/// Packet IP version 6 data.
#[derive(Debug, Clone)]
pub struct SampledIpv6 {
    /// The length of the IP packet excluding lower layer encapsulations.
    pub length: u32,
    /// IP Protocol type (for example, TCP = 6, UDP = 17).
    pub protocol: u32,
    /// Source IP Address.
    pub src_ip: Ipv6Addr,
    /// Destination IP Address.
    pub dst_ip: Ipv6Addr,
    /// TCP/UDP source port number or equivalent.
    pub src_port: u32,
    /// TCP/UDP destination port number or equivalent.
    pub dst_port: u32,
    /// TCP flags.
    pub tcp_flags: u32,
    /// IP priority.
    pub priority: u32,
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

/// Packet data.
#[derive(Debug, Clone)]
pub enum PacketInformationType {
    /// Packet headers are sampled.
    Header(SampledHeader),
    /// Ethernet frame data.
    Ethernet(SampledEthernet),
    /// IP version 4 data.
    Ipv4(SampledIpv4),
    /// IP version 6 data.
    Ipv6(SampledIpv6),
}

/// Extended switch data.
#[derive(Debug, Clone)]
pub struct ExtendedSwitch {
    /// The 802.1Q VLAN id of incoming frame.
    pub src_vlan: u32,
    /// The 802.1p priority of incoming frame.
    pub src_priority: u32,
    /// The 802.1Q VLAN id of outgoing frame.
    pub dst_vlan: u32,
    /// The 802.1p priority of outgoing frame.
    pub dst_priority: u32,
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

/// Extended router data.
#[derive(Debug, Clone)]
pub struct ExtendedRouter {
    /// IP address of next hop router.
    pub nexthop: IpAddr,
    /// Source address prefix mask bits.
    pub src_mask: u32,
    /// Destination address prefix mask bits.
    pub dst_mask: u32,
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

#[derive(Debug, Clone)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

impl From<u32> for AsPathSegmentType {
    fn from(value: u32) -> Self {
        match value {
            1 => AsPathSegmentType::AsSet,
            2 => AsPathSegmentType::AsSequence,
            _ => panic!("Unknown AS path segment type"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AsPathType {
    /// Unordered set of ASs.
    AsSet(HashSet<u32>),
    /// Ordered set of ASs.
    AsSequence(HashSet<u32>),
}

/// Extended router data.
#[derive(Debug, Clone)]
pub struct ExtendedGateway {
    /// Autonomous system number of router.
    pub r#as: u32,
    /// Autonomous system number of source.
    pub src_as: u32,
    /// Autonomous system number of source peer.
    pub src_peer_as: u32,
    /// Autonomous system path to the destination.
    pub dst_as_path: AsPathType,
    /// Communities associated with this route.
    pub communities: Vec<u32>,
    /// LocalPref associated with this route.
    pub localpref: u32,
}

fn parse_extended_gateway(input: &[u8]) -> IResult<&[u8], ExtendedGateway> {
    let (input, as_) = be_u32(input)?;
    let (input, src_as) = be_u32(input)?;
    let (input, src_peer_as) = be_u32(input)?;

    let (input, dst_as_path_type) = map(be_u32, AsPathSegmentType::from).parse(input)?;
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

/// Extended user data.
#[derive(Debug, Clone)]
pub struct ExtendedUser {
    /// User ID associated with packet source.
    pub src_user: String,
    /// User ID associated with packet destination.
    pub dst_user: String,
}

fn parse_extended_user(input: &[u8]) -> IResult<&[u8], ExtendedUser> {
    let (input, src_user) = parse_string(input)?;
    let (input, dst_user) = parse_string(input)?;

    Ok((input, ExtendedUser { src_user, dst_user }))
}

#[derive(Debug, Clone)]
pub enum UrlDirection {
    /// URL is associated with source address.
    Src = 1,
    /// URL is associated with destination address.
    Dst = 2,
}

impl From<u32> for UrlDirection {
    fn from(value: u32) -> Self {
        match value {
            1 => UrlDirection::Src,
            2 => UrlDirection::Dst,
            _ => panic!("Unknown URL direction value"),
        }
    }
}

/// Extended URL data.
#[derive(Debug, Clone)]
pub struct ExtendedUrl {
    /// URL associated with packet source.
    pub direction: UrlDirection,
    /// URL associated with the packet flow.
    pub url: String,
}

fn parse_extended_url(input: &[u8]) -> IResult<&[u8], ExtendedUrl> {
    let (input, direction) = map(be_u32, |v| UrlDirection::from(v)).parse(input)?;
    let (input, url) = parse_string(input)?;

    Ok((input, ExtendedUrl { direction, url }))
}

/// Selected egress queue information.
/// Output port number must be provided in enclosing structure.
/// opaque = flow_data; enterprise = 0; format = 1036
#[derive(Debug, Clone)]
pub struct ExtendedEgressQueue {
    /// Eqress queue number selected for sampled packet.
    pub queue: u32,
}

fn parse_extended_egress_queue(input: &[u8]) -> IResult<&[u8], ExtendedEgressQueue> {
    let (input, queue) = be_u32(input)?;

    Ok((input, ExtendedEgressQueue { queue }))
}

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum Direction {
    Unknown = 0,
    Ingress = 1,
    Egress = 2,
}

impl From<u32> for Direction {
    fn from(value: u32) -> Self {
        match value {
            0 => Direction::Unknown,
            1 => Direction::Ingress,
            2 => Direction::Egress,
            _ => panic!("Unknown direction value"),
        }
    }
}

/// ACL information.
/// Information about ACL rule that matched this packet.
/// opaque = flow_data; enterprise = 0; format = 1037
#[derive(Debug, Clone)]
pub struct ExtendedAcl {
    /// Access list number.
    pub number: u32,
    /// Access list name.
    pub name: String,
    /// unknown = 0, ingress = 1, egress = 2
    pub direction: Direction,
}

fn parse_extended_acl(input: &[u8]) -> IResult<&[u8], ExtendedAcl> {
    let (input, number) = be_u32(input)?;
    let (input, name) = parse_string(input)?;
    let (input, direction) = map(be_u32, |v| Direction::from(v)).parse(input)?;

    Ok((
        input,
        ExtendedAcl {
            number,
            name,
            direction,
        },
    ))
}

/// Software function information.
/// Name of the function in software network stack that discarded the packet.
/// opaque = flow_data; enterprise = 0; format = 1038
#[derive(Debug, Clone)]
pub struct ExtendedFunction {
    pub symbol: String,
}

fn parse_extended_function(input: &[u8]) -> IResult<&[u8], ExtendedFunction> {
    let (input, symbol) = parse_string(input)?;

    Ok((input, ExtendedFunction { symbol }))
}

/// Extended data.
#[derive(Debug, Clone)]
pub enum ExtendedDataType {
    /// Extended switch information.
    Switch(ExtendedSwitch),
    /// Extended router information.
    Router(ExtendedRouter),
    /// Extended gateway router information.
    Gateway(ExtendedGateway),
    /// Extended TACACS/RADIUS user information.
    User(ExtendedUser),
    /// Extended URL information.
    Url(ExtendedUrl),
    /// Extended egress queue information.
    EgressQueue(ExtendedEgressQueue),
    /// Extended ACL information.
    Acl(ExtendedAcl),
    /// Extended software function information.
    Function(ExtendedFunction),
}

/// Format of a single flow sample.
// pub struct FlowSample {
//     /// Incremented with each flow sample generated by this source_id.
//     pub sequence_number: u32,
//     /// sFlowDataSource encoded as follows: The most significant byte of the
//     /// source_id is used to indicate the type of sFlowDataSource (0 = ifIndex,
//     /// 1 = smonVlanDataSource, 2 = entPhysicalEntry) and the lower three bytes
//     /// contain the relevant index value.
//     pub source_id: u32,
//     /// sFlowPacketSamplingRate.
//     pub sampling_rate: u32,
//     /// Total number of packets that could have been sampled (i.e., packets
//     /// skipped by sampling process + total number of samples).
//     pub sample_pool: u32,
//     /// Number times a packet was dropped due to lack of resources.
//     pub drops: u32,
//     /// SNMP ifIndex of input interface. 0 if interface is not known.
//     pub input: u32,
//     /// SNMP ifIndex of output interface, 0 if interface is not known. Set most
//     /// significant bit to indicate multiple destination interfaces (i.e., in
//     /// case of broadcast or multicast) and set lower order bits to indicate
//     /// number of destination interfaces.
//     pub output: u32,
//     /// Information about sampled packet.
//     pub packet_data: PacketInformationType,
//     /// Extended flow information.
//     pub extended_data: Option<ExtendedSwitch>,
// }

/// Generic Interface Counters - see RFC 2233.
/// opaque = counter_data; enterprise = 0; format = 1
#[derive(Debug, Clone)]
pub struct IfCounters {
    pub if_index: u32,
    pub if_type: u32,
    pub if_speed: u64,
    /// derived from MAU MIB (RFC 2668).
    /// 0 = unkown, 1=full-duplex, 2=half-duplex, 3 = in, 4=out
    pub if_direction: u32,
    /// bit field with the following bits assigned.
    /// bit 0 = ifAdminStatus (0 = down, 1 = up)
    /// bit 1 = ifOperStatus (0 = down, 1 = up)
    pub if_status: u32,
    pub if_in_octets: u64,
    pub if_in_ucast_pkts: u32,
    pub if_in_multicast_pkts: u32,
    pub if_in_broadcast_pkts: u32,
    pub if_in_discards: u32,
    pub if_in_errors: u32,
    pub if_in_unknown_protos: u32,
    pub if_out_octets: u64,
    pub if_out_ucast_pkts: u32,
    pub if_out_multicast_pkts: u32,
    pub if_out_broadcast_pkts: u32,
    pub if_out_discards: u32,
    pub if_out_errors: u32,
    pub if_promiscuous_mode: u32,
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

/// Format of a single discarded packet event.
/// opaque = sample_data; enterprise = 0; format = 5
#[derive(Debug, Clone)]
pub struct DiscardedPacket {
    /// Incremented with each discarded packet record generated by this
    /// source_id.
    pub sequence_number: u32,
    /// sFlowDataSource.
    pub source_id: u32,
    /// Number of times that the sFlow agent detected that a discarded packet
    /// record was dropped by the rate limit, or because of a lack of resources.
    /// The drops counter reports the total number of drops detected since the
    /// agent was last reset. Note: An agent that cannot detect drops will
    /// always report zero.
    pub drops: u32,
    /// If set, ifIndex of interface packet was received on. Zero if unknown.
    /// Must identify physical port consistent with flow_sample input interface.
    pub inputifindex: u32,
    /// If set, ifIndex for egress drops. Zero otherwise. Must identify physical
    /// port consistent with flow_sample output interface.
    pub outputifindex: u32,
    /// Reason for dropping packet.
    pub reason: DropReason,
    /// Information about the discarded packet.
    pub discard_records: Vec<String>, // todo
}

/// Ethernet Interface Counters - see RFC 2358.
/// opaque = counter_data; enterprise = 0; format = 2
#[derive(Debug, Clone)]
pub struct EthernetCounters {
    pub dot3_stats_alignment_errors: u32,
    pub dot3_stats_fcs_errors: u32,
    pub dot3_stats_single_collision_frames: u32,
    pub dot3_stats_multiple_collision_frames: u32,
    pub dot3_stats_sqetest_errors: u32,
    pub dot3_stats_deferred_transmissions: u32,
    pub dot3_stats_late_collisions: u32,
    pub dot3_stats_excessive_collisions: u32,
    pub dot3_stats_internal_mac_transmit_errors: u32,
    pub dot3_stats_carrier_sense_errors: u32,
    pub dot3_stats_frame_too_longs: u32,
    pub dot3_stats_internal_mac_receive_errors: u32,
    pub dot3_stats_symbol_errors: u32,
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

/// Token Ring Counters - see RFC 1748.
/// opaque = counter_data; enterprise = 0; format = 3
#[derive(Debug, Clone)]
pub struct TokenringCounters {
    pub dot5_stats_line_errors: u32,
    pub dot5_stats_burst_errors: u32,
    pub dot5_stats_ac_errors: u32,
    pub dot5_stats_abort_trans_errors: u32,
    pub dot5_stats_internal_errors: u32,
    pub dot5_stats_lost_frame_errors: u32,
    pub dot5_stats_receive_congestions: u32,
    pub dot5_stats_frame_copied_errors: u32,
    pub dot5_stats_token_errors: u32,
    pub dot5_stats_soft_errors: u32,
    pub dot5_stats_hard_errors: u32,
    pub dot5_stats_signal_loss: u32,
    pub dot5_stats_transmit_beacons: u32,
    pub dot5_stats_recoveries: u32,
    pub dot5_stats_lobe_wires: u32,
    pub dot5_stats_removes: u32,
    pub dot5_stats_singles: u32,
    pub dot5_stats_freq_errors: u32,
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

/// 100 BaseVG interface counters - see RFC 2020.
/// opaque = counter_data; enterprise = 0; format = 4
#[derive(Debug, Clone)]
pub struct VgCounters {
    pub dot12_in_high_priority_frames: u32,
    pub dot12_in_high_priority_octets: u64,
    pub dot12_in_norm_priority_frames: u32,
    pub dot12_in_norm_priority_octets: u64,
    pub dot12_in_ipm_errors: u32,
    pub dot12_in_oversize_frame_errors: u32,
    pub dot12_in_data_errors: u32,
    pub dot12_in_null_addressed_frames: u32,
    pub dot12_out_high_priority_frames: u32,
    pub dot12_out_high_priority_octets: u64,
    pub dot12_transition_into_training: u32,
    pub dot12_hc_in_high_priority_octets: u64,
    pub dot12_hc_in_norm_priority_octets: u64,
    pub dot12_hc_out_high_priority_octets: u64,
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

/// VLAN Counters.
/// opaque = counter_data; enterprise = 0; format = 5
#[derive(Debug, Clone)]
pub struct VlanCounters {
    pub vlan_id: u32,
    pub octets: u64,
    pub ucast_pkts: u32,
    pub multicast_pkts: u32,
    pub broadcast_pkts: u32,
    pub discards: u32,
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

/// Processor Information.
/// opaque = counter_data; enterprise = 0; format = 1001
#[derive(Debug, Clone)]
pub struct Processor {
    /// 5 second average CPU utilization.
    pub avg_5s_cpu: i32,
    /// 1 minute average CPU utilization.
    pub avg_1m_cpu: i32,
    /// 5 minute average CPU utilization.
    pub avg_5m_cpu: i32,
    /// total memory (in bytes).
    pub total_memory: u64,
    /// free memory (in bytes).
    pub free_memory: u64,
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
