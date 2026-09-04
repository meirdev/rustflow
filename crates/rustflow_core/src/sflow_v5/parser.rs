use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{fail, map, map_res, peek, verify};
use nom::multi::{count, many1};
use nom::number::complete::{be_i32, be_u32, be_u64, be_u128};
use nom::{IResult, Parser, ToUsize};
use num_enum::TryFromPrimitive;
use serde::Serialize;

use crate::common::parser::{ipv4_addr, ipv6_addr, macaddr6};

pub const SFLOW_V5_VERSION: u32 = 5;

const IPV4: u32 = 1;
const IPV6: u32 = 2;

pub struct SflowV5Parser;

impl SflowV5Parser {
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], SFlowV5> {
        parse_sflow_v5(input)
    }
}

impl Default for SflowV5Parser {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum DataValue {
    Null,
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    MacAddr(MacAddr6),
    U8(u8),
    U16(u16),
    U32(u32),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

#[derive(Debug, Clone, Serialize)]
pub struct SFlowV5 {
    pub version: u32,
    pub agent_address: IpAddr,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub samples: Vec<Sample>,
}

fn parse_sflow_v5(input: &[u8]) -> IResult<&[u8], SFlowV5> {
    let (input, version) = verify(be_u32, |i| *i == SFLOW_V5_VERSION).parse(input)?;
    let (input, agent_address) = parse_address(input)?;
    let (input, sub_agent_id) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, uptime) = be_u32(input)?;
    let (input, sample_count) = be_u32(input)?;

    let (input, samples) = count(
        |v| {
            let (input, data_format) = peek(be_u32).parse(v)?;

            match SampleFormat::try_from(data_format) {
                Ok(SampleFormat::Flow) => {
                    let (input, v) = parse_flow_sample(v)?;
                    Ok((input, Sample::Flow(v)))
                }
                Ok(SampleFormat::Counter) => {
                    let (input, v) = parse_counter_sample(v)?;
                    Ok((input, Sample::Counter(v)))
                }
                Ok(SampleFormat::ExpandedFlow) => {
                    let (input, v) = parse_expanded_flow_sample(v)?;
                    Ok((input, Sample::ExpandedFlow(v)))
                }
                Ok(SampleFormat::ExpandedCounter) | Ok(SampleFormat::Drop) | Err(_) => {
                    // Every sample is `data_format` + `opaque sample_data<>`,
                    // so an unsupported format is skipped by reading only
                    // the format and length words: `length` already covers
                    // everything after it, sequence number and source id
                    // included.
                    let (input, _format) = be_u32(input)?;
                    let (input, length) = be_u32(input)?;
                    let (input, data) = take(length as usize)(input)?;
                    Ok((input, Sample::Unknown(data.to_vec())))
                }
            }
        },
        sample_count.to_usize(),
    )
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

#[derive(Debug, Clone, Serialize)]
pub enum Sample {
    Flow(FlowSample),
    Counter(CounterSample),
    ExpandedFlow(ExpandedFlowSample),
    Drop(DropSample),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum SampleFormat {
    Flow = 1,
    Counter = 2,
    ExpandedFlow = 3,
    ExpandedCounter = 4,
    Drop = 5,
}

#[derive(Debug, Clone, Serialize)]
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

    let (input, (source_id_type, source_id_value)) = match SampleFormat::try_from(format) {
        Ok(SampleFormat::Flow | SampleFormat::Counter) => {
            let (input, source_id) = be_u32(input)?;

            let source_id_type = source_id >> 24;
            let source_id_value = source_id & 0x00ffffff;

            (input, (source_id_type, source_id_value))
        }
        Ok(SampleFormat::ExpandedFlow | SampleFormat::ExpandedCounter | SampleFormat::Drop) => {
            let (input, source_id_type) = be_u32(input)?;
            let (input, source_id_value) = be_u32(input)?;

            (input, (source_id_type, source_id_value))
        }
        Err(_) => fail().parse(input)?,
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

#[derive(Debug, Clone, Serialize)]
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
    let (input, records) = count(parse_flow_record, flow_records_count.to_usize()).parse(input)?;

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

#[derive(Debug, Clone, Serialize)]
pub struct CounterSample {
    pub header: SampleHeader,
    pub records: Vec<CounterRecord>,
}

fn parse_counter_sample(input: &[u8]) -> IResult<&[u8], CounterSample> {
    let (input, header) = parse_sample_header(input)?;
    let (input, records_count) = be_u32(input)?;
    let (input, records) = count(parse_counter_record, records_count.to_usize()).parse(input)?;

    Ok((input, CounterSample { header, records }))
}

#[derive(Debug, Clone, Serialize)]
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
    let (input, records) = count(parse_flow_record, flow_records_count.to_usize()).parse(input)?;

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

#[derive(Debug, Clone, Serialize)]
pub struct DropSample {
    pub header: SampleHeader,
    pub drops: u32,
    pub input: u32,
    pub output: u32,
    pub reason: DropReason,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
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
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRecord {
    pub header: RecordHeader,
    pub data: FlowRecordType,
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data) = map(take(header.length as usize), |v| {
        match FlowType::try_from(header.data_format) {
            Ok(FlowType::SampledHeader) => {
                let (_input, v) = parse_sampled_header(v)?;
                Ok(FlowRecordType::SampledHeader(v))
            }
            Ok(FlowType::SampledEthernet) => {
                let (_input, v) = parse_sampled_ethernet(v)?;
                Ok(FlowRecordType::SampledEthernet(v))
            }
            Ok(FlowType::SampledIpv4) => {
                let (_input, v) = parse_sampled_ipv4(v)?;
                Ok(FlowRecordType::SampledIpv4(v))
            }
            Ok(FlowType::SampledIpv6) => {
                let (_input, v) = parse_sampled_ipv6(v)?;
                Ok(FlowRecordType::SampledIpv6(v))
            }
            Ok(FlowType::ExtendedSwitch) => {
                let (_input, v) = parse_extended_switch(v)?;
                Ok(FlowRecordType::ExtendedSwitch(v))
            }
            Ok(FlowType::ExtendedRouter) => {
                let (_input, v) = parse_extended_router(v)?;
                Ok(FlowRecordType::ExtendedRouter(v))
            }
            Ok(FlowType::ExtendedGateway) => {
                let (_input, v) = parse_extended_gateway(v)?;
                Ok(FlowRecordType::ExtendedGateway(v))
            }
            Ok(FlowType::ExtendedUser) => {
                let (_input, v) = parse_extended_user(v)?;
                Ok(FlowRecordType::ExtendedUser(v))
            }
            Ok(FlowType::ExtendedUrl) => {
                let (_input, v) = parse_extended_url(v)?;
                Ok(FlowRecordType::ExtendedUrl(v))
            }
            Ok(FlowType::ExtendedEgressQueue) => {
                let (_input, v) = parse_extended_egress_queue(v)?;
                Ok(FlowRecordType::ExtendedEgressQueue(v))
            }
            Ok(FlowType::ExtendedAcl) => {
                let (_input, v) = parse_extended_acl(v)?;
                Ok(FlowRecordType::ExtendedAcl(v))
            }
            Ok(FlowType::ExtendedFunction) => {
                let (_input, v) = parse_extended_function(v)?;
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

#[derive(Debug, Clone, Serialize)]
pub enum CounterRecordType {
    IfCounters(IfCounters),
    EthernetCounters(EthernetCounters),
    TokenringCounters(TokenringCounters),
    VgCounters(VgCounters),
    VlanCounters(VlanCounters),
    Processor(Processor),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum CounterType {
    IfCounters = 1,
    EthernetCounters = 2,
    TokenringCounters = 3,
    VgCounters = 4,
    VlanCounters = 5,
    Processor = 1001,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterRecord {
    pub header: RecordHeader,
    pub data: Vec<CounterRecordType>,
}

fn parse_counter_record(input: &[u8]) -> IResult<&[u8], CounterRecord> {
    let (input, header) = parse_record_header(input)?;
    let (input, data) = take(header.length as usize)(input)?;

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
            let (input, data) = take(v.len())(v)?;
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

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
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
    Aal5Ip = 10,
    Ipv4 = 11,
    Ipv6 = 12,
    Mpls = 13,
    Pos = 14,
}

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum DropReason {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragNeeded = 4,
    SrcRouteFailed = 5,
    DstNetUnknown = 6,
    DstHostUnknown = 7,
    SrcHostIsolated = 8,
    DstNetProhibited = 9,
    DstHostProhibited = 10,
    DstNetTosUnreachable = 11,
    DstHostTosUnreachable = 12,
    CommAdminProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
    Unknown = 256,
    TtlExceeded = 257,
    Acl = 258,
    NoBufferSpace = 259,
    Red = 260,
    TrafficShaping = 261,
    PktTooBig = 262,
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
    UnknownL2 = 284,
    UnknownL3 = 285,
    UnknownL3Exception = 286,
    UnknownBuffer = 287,
    UnknownTunnel = 288,
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

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
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

#[derive(Debug, Clone, Serialize)]
pub struct SampledHeader {
    pub protocol: HeaderProtocol,
    pub frame_length: u32,
    pub stripped: u32,
    pub header: Vec<u8>,
}

fn parse_sampled_header(input: &[u8]) -> IResult<&[u8], SampledHeader> {
    let (input, protocol) = map_res(be_u32, |v| v.try_into()).parse(input)?;
    let (input, frame_length) = be_u32(input)?;
    let (input, stripped) = be_u32(input)?;
    let (input, original_length) = be_u32(input)?;
    let (input, header) = take(original_length.to_usize())(input)?;

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

#[derive(Debug, Clone, Serialize)]
pub struct SampledEthernet {
    pub length: u32,
    pub src_mac: MacAddr6,
    pub dst_mac: MacAddr6,
    pub r#type: u32,
}

fn parse_sampled_ethernet(input: &[u8]) -> IResult<&[u8], SampledEthernet> {
    let (input, legnth) = be_u32(input)?;
    let (input, src_mac) = macaddr6(input)?;
    let (input, dst_mac) = macaddr6(input)?;
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

#[derive(Debug, Clone, Serialize)]
pub struct SampledIpv4 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub tos: u32,
}

fn parse_sampled_ipv4(input: &[u8]) -> IResult<&[u8], SampledIpv4> {
    let (input, length) = be_u32(input)?;
    let (input, protocol) = be_u32(input)?;
    let (input, src_ip) = ipv4_addr(input)?;
    let (input, dst_ip) = ipv4_addr(input)?;
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

#[derive(Debug, Clone, Serialize)]
pub struct SampledIpv6 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub priority: u32,
}

fn parse_sampled_ipv6(input: &[u8]) -> IResult<&[u8], SampledIpv6> {
    let (input, length) = be_u32(input)?;
    let (input, protocol) = be_u32(input)?;
    let (input, src_ip) = ipv6_addr(input)?;
    let (input, dst_ip) = ipv6_addr(input)?;
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

#[derive(Debug, Clone, Serialize)]
pub enum PacketInformationType {
    Header(SampledHeader),
    Ethernet(SampledEthernet),
    Ipv4(SampledIpv4),
    Ipv6(SampledIpv6),
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedSwitch {
    pub src_vlan: u32,
    pub src_priority: u32,
    pub dst_vlan: u32,
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

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedRouter {
    pub nexthop: IpAddr,
    pub src_mask: u32,
    pub dst_mask: u32,
}

fn parse_address(input: &[u8]) -> IResult<&[u8], IpAddr> {
    let (input, address_type) = be_u32(input)?;
    match address_type {
        IPV4 => {
            let (input, addr) = be_u32(input)?;
            Ok((input, IpAddr::V4(Ipv4Addr::from(addr))))
        }
        IPV6 => {
            let (input, addr) = be_u128(input)?;
            Ok((input, IpAddr::V6(Ipv6Addr::from(addr))))
        }
        _ => fail().parse(input),
    }
}

fn parse_extended_router(input: &[u8]) -> IResult<&[u8], ExtendedRouter> {
    let (input, nexthop) = parse_address(input)?;
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

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

#[derive(Debug, Clone, Serialize)]
pub enum AsPathType {
    AsSet(HashSet<u32>),
    AsSequence(Vec<u32>),
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedGateway {
    pub nexthop: IpAddr,
    pub r#as: u32,
    pub src_as: u32,
    pub src_peer_as: u32,
    pub dst_as_path: Vec<AsPathType>,
    pub communities: Vec<u32>,
    pub localpref: u32,
}

fn parse_as_path_segment(input: &[u8]) -> IResult<&[u8], AsPathType> {
    let (input, segment_type) = map_res(be_u32, AsPathSegmentType::try_from).parse(input)?;
    let (input, length) = be_u32(input)?;
    let (input, ases) = count(be_u32, length.to_usize()).parse(input)?;

    let segment = match segment_type {
        AsPathSegmentType::AsSet => AsPathType::AsSet(ases.into_iter().collect()),
        AsPathSegmentType::AsSequence => AsPathType::AsSequence(ases),
    };

    Ok((input, segment))
}

fn parse_extended_gateway(input: &[u8]) -> IResult<&[u8], ExtendedGateway> {
    let (input, nexthop) = parse_address(input)?;
    let (input, as_) = be_u32(input)?;
    let (input, src_as) = be_u32(input)?;
    let (input, src_peer_as) = be_u32(input)?;

    let (input, dst_as_path_length) = be_u32(input)?;
    let (input, dst_as_path) =
        count(parse_as_path_segment, dst_as_path_length.to_usize()).parse(input)?;

    let (input, communities_length) = be_u32(input)?;
    let (input, communities) = count(be_u32, communities_length.to_usize()).parse(input)?;

    let (input, localpref) = be_u32(input)?;

    Ok((
        input,
        ExtendedGateway {
            nexthop,
            r#as: as_,
            src_as,
            src_peer_as,
            dst_as_path,
            communities,
            localpref,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedUser {
    pub src_charset: u32,
    pub src_user: String,
    pub dst_charset: u32,
    pub dst_user: String,
}

fn parse_extended_user(input: &[u8]) -> IResult<&[u8], ExtendedUser> {
    let (input, src_charset) = be_u32(input)?;
    let (input, src_user) = parse_string(input)?;
    let (input, dst_charset) = be_u32(input)?;
    let (input, dst_user) = parse_string(input)?;

    Ok((
        input,
        ExtendedUser {
            src_charset,
            src_user,
            dst_charset,
            dst_user,
        },
    ))
}

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum UrlDirection {
    Src = 1,
    Dst = 2,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedUrl {
    pub direction: UrlDirection,
    pub url: String,
}

fn parse_extended_url(input: &[u8]) -> IResult<&[u8], ExtendedUrl> {
    let (input, direction) = map_res(be_u32, |v| v.try_into()).parse(input)?;
    let (input, url) = parse_string(input)?;

    Ok((input, ExtendedUrl { direction, url }))
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedEgressQueue {
    pub queue: u32,
}

fn parse_extended_egress_queue(input: &[u8]) -> IResult<&[u8], ExtendedEgressQueue> {
    let (input, queue) = be_u32(input)?;

    Ok((input, ExtendedEgressQueue { queue }))
}

#[derive(Debug, Clone, Serialize, TryFromPrimitive)]
#[repr(u32)]
pub enum Direction {
    Unknown = 0,
    Ingress = 1,
    Egress = 2,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedAcl {
    pub number: u32,
    pub name: String,
    pub direction: Direction,
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

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedFunction {
    pub symbol: String,
}

fn parse_extended_function(input: &[u8]) -> IResult<&[u8], ExtendedFunction> {
    let (input, symbol) = parse_string(input)?;

    Ok((input, ExtendedFunction { symbol }))
}

#[derive(Debug, Clone, Serialize)]
pub enum ExtendedDataType {
    Switch(ExtendedSwitch),
    Router(ExtendedRouter),
    Gateway(ExtendedGateway),
    User(ExtendedUser),
    Url(ExtendedUrl),
    EgressQueue(ExtendedEgressQueue),
    Acl(ExtendedAcl),
    Function(ExtendedFunction),
}

#[derive(Debug, Clone, Serialize)]
pub struct IfCounters {
    pub if_index: u32,
    pub if_type: u32,
    pub if_speed: u64,
    pub if_direction: u32,
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

#[derive(Debug, Clone, Serialize)]
pub struct DiscardedPacket {
    pub sequence_number: u32,
    pub source_id: u32,
    pub drops: u32,
    pub inputifindex: u32,
    pub outputifindex: u32,
    pub reason: DropReason,
    pub discard_records: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct Processor {
    pub avg_5s_cpu: i32,
    pub avg_1m_cpu: i32,
    pub avg_5m_cpu: i32,
    pub total_memory: u64,
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

    // RFC 4506 sections 4.10 and 4.11: pad to a multiple of four bytes.
    let padding = (4 - (length as usize) % 4) % 4;
    let (input, _) = take(padding.min(input.len()))(input)?;

    Ok((input, string))
}
