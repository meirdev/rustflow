use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::Serialize;
use strum::Display;

use crate::common::InformationElement;
use crate::common::timeout_map::TimeoutHashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowType {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

/// Key for sampling rate cache: (exporter_address,
/// source_id/observation_domain_id)
pub type SamplingRateCacheKey = (IpAddr, u32);

pub struct SamplingRateCache {
    cache: TimeoutHashMap<SamplingRateCacheKey, u32>,
}

impl SamplingRateCache {
    pub fn new(timeout: Duration) -> Self {
        Self {
            cache: TimeoutHashMap::new(timeout),
        }
    }

    pub fn get(&self, key: &SamplingRateCacheKey) -> Option<u32> {
        self.cache.get(key).copied()
    }

    pub fn set(&mut self, key: SamplingRateCacheKey, rate: u32) {
        self.cache.insert(key, rate);
    }

    pub fn cleanup(&mut self) {
        self.cache.cleanup();
    }
}

impl Default for SamplingRateCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommonFlow {
    pub flow_type: FlowType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_received_ns: Option<i64>,

    pub sequence_num: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_rate: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampler_address: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_flow_start_ns: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_flow_end_ns: Option<i64>,

    pub bytes: u64,

    pub packets: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_addr: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_addr: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<MacAddr6>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<MacAddr6>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub etype: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_if: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_if: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_tos: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_ttl: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_flow_label: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_offset: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_as: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_as: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_net: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_net: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgp_next_hop: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_vlan: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_vlan: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_domain_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u16>,

    /// PSAMP (RFC 5476): the Selection Sequence that selected this packet.
    /// Set only for Packet Reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_sequence_id: Option<u64>,
}

impl Default for CommonFlow {
    fn default() -> Self {
        Self {
            flow_type: FlowType::NetflowV5,
            time_received_ns: None,
            sequence_num: 0,
            sampling_rate: None,
            sampler_address: None,
            time_flow_start_ns: None,
            time_flow_end_ns: None,
            bytes: 0,
            packets: 0,
            src_addr: None,
            dst_addr: None,
            src_mac: None,
            dst_mac: None,
            etype: None,
            proto: None,
            src_port: None,
            dst_port: None,
            in_if: None,
            out_if: None,
            ip_tos: None,
            ip_ttl: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            ipv6_flow_label: None,
            fragment_id: None,
            fragment_offset: None,
            src_as: None,
            dst_as: None,
            next_hop: None,
            src_net: None,
            dst_net: None,
            bgp_next_hop: None,
            src_vlan: None,
            dst_vlan: None,
            observation_domain_id: None,
            template_id: None,
            selection_sequence_id: None,
        }
    }
}

impl CommonFlow {
    pub fn new(flow_type: FlowType) -> Self {
        Self {
            flow_type,
            ..Default::default()
        }
    }

    pub fn with_time_received(mut self, time: DateTime<Utc>) -> Self {
        self.time_received_ns = Some(time.timestamp_nanos_opt().unwrap_or(0));
        self
    }
}

use crate::netflow_v5::parser::{FlowRecord as V5FlowRecord, Header as V5Header};

pub struct NetFlowV5Context<'a> {
    pub header: &'a V5Header,
    pub sampler_address: Option<IpAddr>,
}

impl NetFlowV5Context<'_> {
    /// Convert uptime-based timestamp to absolute nanoseconds since epoch.
    ///
    /// In NetFlow v5, `first` and `last` are system uptime values in
    /// milliseconds. We convert them to absolute time using:
    /// `absolute_time = unix_time - (sys_uptime - uptime_value)`
    fn uptime_to_absolute_ns(&self, uptime_ms: i64) -> Option<i64> {
        let unix_time_ns =
            (self.header.unix_secs as i64) * 1_000_000_000 + (self.header.unix_nsecs as i64);
        let sys_uptime_ms = self.header.sys_uptime.timestamp_millis();
        let offset_ms = sys_uptime_ms - uptime_ms;
        Some(unix_time_ns - (offset_ms * 1_000_000))
    }

    pub fn convert(&self, record: &V5FlowRecord) -> CommonFlow {
        CommonFlow {
            flow_type: FlowType::NetflowV5,
            time_received_ns: None,
            sequence_num: self.header.flow_sequence,
            sampling_rate: Some(self.header.sampling_interval as u32),
            sampler_address: self.sampler_address,
            time_flow_start_ns: self.uptime_to_absolute_ns(record.first.timestamp_millis()),
            time_flow_end_ns: self.uptime_to_absolute_ns(record.last.timestamp_millis()),
            bytes: record.d_ockts as u64,
            packets: record.d_pkts as u64,
            src_addr: Some(IpAddr::V4(record.srcaddr)),
            dst_addr: Some(IpAddr::V4(record.dstaddr)),
            src_mac: None,
            dst_mac: None,
            etype: Some(0x0800),
            proto: Some(record.prot),
            src_port: Some(record.srcport),
            dst_port: Some(record.dstport),
            in_if: Some(record.input as u32),
            out_if: Some(record.output as u32),
            ip_tos: Some(record.tos),
            ip_ttl: None,
            tcp_flags: Some(u16::from(record.tcp_flags)),
            icmp_type: None,
            icmp_code: None,
            ipv6_flow_label: None,
            fragment_id: None,
            fragment_offset: None,
            src_as: Some(record.src_as as u32),
            dst_as: Some(record.dst_as as u32),
            next_hop: Some(IpAddr::V4(record.nexthop)),
            src_net: Some(record.src_mask),
            dst_net: Some(record.dst_mask),
            bgp_next_hop: None,
            src_vlan: None,
            dst_vlan: None,
            observation_domain_id: None,
            template_id: None, // NetFlow v5 has no templates
            selection_sequence_id: None,
        }
    }
}

use crate::netflow_v9::parser::{
    DataRecord as V9DataRecord, FieldValue as V9FieldValue, Header as V9Header,
};

pub struct NetFlowV9Context<'a> {
    pub header: &'a V9Header,
    pub sampler_address: Option<IpAddr>,
    pub sampling_rate: Option<u32>,
}

impl NetFlowV9Context<'_> {
    /// Convert uptime-based timestamp to absolute nanoseconds since epoch.
    ///
    /// In NetFlow v9, `FlowStartSysUpTime` and `FlowEndSysUpTime` are system
    /// uptime values in milliseconds. We convert them to absolute time using:
    /// `absolute_time = unix_seconds - (system_uptime - uptime_value)`
    fn uptime_to_absolute_ns(&self, uptime_ms: u32) -> Option<i64> {
        let unix_time_ns = self.header.unix_seconds.timestamp_nanos_opt()?;
        let offset_ms = self.header.system_uptime as i64 - uptime_ms as i64;
        Some(unix_time_ns - (offset_ms * 1_000_000))
    }

    pub fn convert(&self, record: &V9DataRecord, template_id: u16) -> CommonFlow {
        use InformationElement::*;

        let mut flow = CommonFlow::new(FlowType::NetflowV9);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = self.sampler_address;
        flow.observation_domain_id = Some(self.header.source_id);
        flow.template_id = Some(template_id);

        if let Some(rate) = self.sampling_rate {
            flow.sampling_rate = Some(rate);
        }

        for (field_type, _, value) in &record.0 {
            if let Some(ie) = InformationElement::from_id(*field_type) {
                match ie {
                    OctetDeltaCount => flow.bytes = extract_u64(value),
                    PacketDeltaCount => flow.packets = extract_u64(value),
                    ProtocolIdentifier => flow.proto = extract_u8(value),
                    IpClassOfService => flow.ip_tos = extract_u8(value),
                    TcpControlBits => flow.tcp_flags = extract_u16(value),
                    SourceTransportPort => flow.src_port = extract_u16(value),
                    SourceIpv4Address => {
                        if let V9FieldValue::Ipv4Address(addr) = value {
                            flow.src_addr = Some(IpAddr::V4(*addr));
                            flow.etype = Some(0x0800);
                        }
                    }
                    SourceIpv4PrefixLength => flow.src_net = extract_u8(value),
                    IngressInterface => flow.in_if = extract_u32(value),
                    DestinationTransportPort => flow.dst_port = extract_u16(value),
                    DestinationIpv4Address => {
                        if let V9FieldValue::Ipv4Address(addr) = value {
                            flow.dst_addr = Some(IpAddr::V4(*addr));
                        }
                    }
                    DestinationIpv4PrefixLength => flow.dst_net = extract_u8(value),
                    EgressInterface => flow.out_if = extract_u32(value),
                    IpNextHopIpv4Address => {
                        if let V9FieldValue::Ipv4Address(addr) = value {
                            flow.next_hop = Some(IpAddr::V4(*addr));
                        }
                    }
                    BgpSourceAsNumber => flow.src_as = extract_u32(value),
                    BgpDestinationAsNumber => flow.dst_as = extract_u32(value),
                    BgpNextHopIpv4Address => {
                        if let V9FieldValue::Ipv4Address(addr) = value {
                            flow.bgp_next_hop = Some(IpAddr::V4(*addr));
                        }
                    }
                    FlowStartSysUpTime => {
                        flow.time_flow_start_ns =
                            extract_u32(value).and_then(|v| self.uptime_to_absolute_ns(v));
                    }
                    FlowEndSysUpTime => {
                        flow.time_flow_end_ns =
                            extract_u32(value).and_then(|v| self.uptime_to_absolute_ns(v));
                    }
                    FlowStartSeconds
                    | FlowStartMilliseconds
                    | FlowStartMicroseconds
                    | FlowStartNanoseconds => {
                        flow.time_flow_start_ns = extract_datetime_ns(value);
                    }
                    FlowEndSeconds | FlowEndMilliseconds | FlowEndMicroseconds
                    | FlowEndNanoseconds => {
                        flow.time_flow_end_ns = extract_datetime_ns(value);
                    }
                    SourceIpv6Address => {
                        if let V9FieldValue::Ipv6Address(addr) = value {
                            flow.src_addr = Some(IpAddr::V6(*addr));
                            flow.etype = Some(0x86dd);
                        }
                    }
                    DestinationIpv6Address => {
                        if let V9FieldValue::Ipv6Address(addr) = value {
                            flow.dst_addr = Some(IpAddr::V6(*addr));
                        }
                    }
                    SourceIpv6PrefixLength => flow.src_net = extract_u8(value),
                    DestinationIpv6PrefixLength => flow.dst_net = extract_u8(value),
                    FlowLabelIpv6 => flow.ipv6_flow_label = extract_u32(value),
                    IcmpTypeCodeIpv4 => {
                        if let Some(v) = extract_u16(value) {
                            flow.icmp_type = Some((v >> 8) as u8);
                            flow.icmp_code = Some((v & 0xff) as u8);
                        }
                    }
                    IcmpTypeIpv4 | IcmpTypeIpv6 => flow.icmp_type = extract_u8(value),
                    IcmpCodeIpv4 | IcmpCodeIpv6 => flow.icmp_code = extract_u8(value),
                    SamplingInterval | SamplingPacketInterval | SamplerRandomInterval => {
                        if self.sampling_rate.is_none() {
                            flow.sampling_rate = extract_u32(value);
                        }
                    }
                    SrcVlan => flow.src_vlan = extract_u16(value),
                    DstVlan => flow.dst_vlan = extract_u16(value),
                    IpNextHopIpv6Address => {
                        if let V9FieldValue::Ipv6Address(addr) = value {
                            flow.next_hop = Some(IpAddr::V6(*addr));
                        }
                    }
                    BgpNextHopIpv6Address => {
                        if let V9FieldValue::Ipv6Address(addr) = value {
                            flow.bgp_next_hop = Some(IpAddr::V6(*addr));
                        }
                    }
                    MinimumTtl | MaximumTtl => flow.ip_ttl = extract_u8(value),
                    FragmentIdentification => flow.fragment_id = extract_u32(value),
                    SourceMacAddress | PostSourceMacAddress => {
                        if let V9FieldValue::MacAddress(mac) = value {
                            flow.src_mac = Some(*mac);
                        }
                    }
                    DestinationMacAddress | PostDestinationMacAddress => {
                        if let V9FieldValue::MacAddress(mac) = value {
                            flow.dst_mac = Some(*mac);
                        }
                    }
                    _ => {}
                }
            }
        }

        flow
    }
}

pub fn extract_v9_sampling_rate(record: &V9DataRecord) -> Option<u32> {
    let sampling_interval_id: u16 = InformationElement::SamplingInterval.into();
    let sampling_packet_interval_id: u16 = InformationElement::SamplingPacketInterval.into();
    let sampler_random_interval_id: u16 = InformationElement::SamplerRandomInterval.into();
    for (field_type, _, value) in &record.0 {
        if *field_type == sampling_interval_id
            || *field_type == sampling_packet_interval_id
            || *field_type == sampler_random_interval_id
        {
            return extract_u32(value);
        }
    }
    None
}

fn extract_u8(value: &V9FieldValue) -> Option<u8> {
    match value {
        V9FieldValue::Unsigned8(v) => Some(*v),
        V9FieldValue::Unsigned16(v) => Some(*v as u8),
        V9FieldValue::Unsigned32(v) => Some(*v as u8),
        V9FieldValue::Unsigned64(v) => Some(*v as u8),
        _ => None,
    }
}

fn extract_u16(value: &V9FieldValue) -> Option<u16> {
    match value {
        V9FieldValue::Unsigned8(v) => Some(*v as u16),
        V9FieldValue::Unsigned16(v) => Some(*v),
        V9FieldValue::Unsigned32(v) => Some(*v as u16),
        V9FieldValue::Unsigned64(v) => Some(*v as u16),
        _ => None,
    }
}

fn extract_u32(value: &V9FieldValue) -> Option<u32> {
    match value {
        V9FieldValue::Unsigned8(v) => Some(*v as u32),
        V9FieldValue::Unsigned16(v) => Some(*v as u32),
        V9FieldValue::Unsigned32(v) => Some(*v),
        V9FieldValue::Unsigned64(v) => Some(*v as u32),
        _ => None,
    }
}

fn extract_u64(value: &V9FieldValue) -> u64 {
    match value {
        V9FieldValue::Unsigned8(v) => *v as u64,
        V9FieldValue::Unsigned16(v) => *v as u64,
        V9FieldValue::Unsigned32(v) => *v as u64,
        V9FieldValue::Unsigned64(v) => *v,
        _ => 0,
    }
}

fn extract_datetime_ns(value: &V9FieldValue) -> Option<i64> {
    match value {
        V9FieldValue::DateTimeSeconds(dt)
        | V9FieldValue::DateTimeMilliseconds(dt)
        | V9FieldValue::DateTimeMicroseconds(dt)
        | V9FieldValue::DateTimeNanoseconds(dt) => dt.timestamp_nanos_opt(),
        _ => None,
    }
}

use crate::ipfix::parser::{
    DataRecord as IpfixDataRecord, FieldValue as IpfixFieldValue, Header as IpfixHeader,
};

pub struct IpfixContext<'a> {
    pub header: &'a IpfixHeader,
    pub sampler_address: Option<IpAddr>,
    pub sampling_rate: Option<u32>,
}

impl IpfixContext<'_> {
    /// Convert delta microseconds to absolute nanoseconds since epoch.
    ///
    /// Delta fields represent time backwards from export_time:
    /// `absolute_time = export_time - delta_microseconds`
    fn delta_to_absolute_ns(&self, delta_us: u32) -> Option<i64> {
        let export_time_ns = self.header.export_time.timestamp_nanos_opt()?;
        Some(export_time_ns - (delta_us as i64 * 1_000))
    }

    pub fn convert(&self, record: &IpfixDataRecord, template_id: u16) -> CommonFlow {
        use InformationElement::*;

        let mut flow = CommonFlow::new(FlowType::Ipfix);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = self.sampler_address;
        flow.observation_domain_id = Some(self.header.observation_domain_id);
        flow.template_id = Some(template_id);

        if let Some(rate) = self.sampling_rate {
            flow.sampling_rate = Some(rate);
        }

        for (field, _, value) in &record.0 {
            let field_type = &field.information_element_identifier;
            if let Some(ie) = InformationElement::from_id(*field_type) {
                match ie {
                    OctetDeltaCount => flow.bytes = ipfix_extract_u64(value),
                    PacketDeltaCount => flow.packets = ipfix_extract_u64(value),
                    ProtocolIdentifier => flow.proto = ipfix_extract_u8(value),
                    IpClassOfService => flow.ip_tos = ipfix_extract_u8(value),
                    TcpControlBits => flow.tcp_flags = ipfix_extract_u16(value),
                    SourceTransportPort => flow.src_port = ipfix_extract_u16(value),
                    SourceIpv4Address => {
                        if let IpfixFieldValue::Ipv4Address(addr) = value {
                            flow.src_addr = Some(IpAddr::V4(*addr));
                            flow.etype = Some(0x0800);
                        }
                    }
                    SourceIpv4PrefixLength => flow.src_net = ipfix_extract_u8(value),
                    IngressInterface => flow.in_if = ipfix_extract_u32(value),
                    DestinationTransportPort => flow.dst_port = ipfix_extract_u16(value),
                    DestinationIpv4Address => {
                        if let IpfixFieldValue::Ipv4Address(addr) = value {
                            flow.dst_addr = Some(IpAddr::V4(*addr));
                        }
                    }
                    DestinationIpv4PrefixLength => flow.dst_net = ipfix_extract_u8(value),
                    EgressInterface => flow.out_if = ipfix_extract_u32(value),
                    IpNextHopIpv4Address => {
                        if let IpfixFieldValue::Ipv4Address(addr) = value {
                            flow.next_hop = Some(IpAddr::V4(*addr));
                        }
                    }
                    BgpSourceAsNumber => flow.src_as = ipfix_extract_u32(value),
                    BgpDestinationAsNumber => flow.dst_as = ipfix_extract_u32(value),
                    BgpNextHopIpv4Address => {
                        if let IpfixFieldValue::Ipv4Address(addr) = value {
                            flow.bgp_next_hop = Some(IpAddr::V4(*addr));
                        }
                    }
                    FlowStartSeconds
                    | FlowStartMilliseconds
                    | FlowStartMicroseconds
                    | FlowStartNanoseconds => {
                        flow.time_flow_start_ns = ipfix_extract_datetime_ns(value);
                    }
                    FlowEndSeconds | FlowEndMilliseconds | FlowEndMicroseconds
                    | FlowEndNanoseconds => {
                        flow.time_flow_end_ns = ipfix_extract_datetime_ns(value);
                    }
                    FlowStartDeltaMicroseconds => {
                        flow.time_flow_start_ns =
                            ipfix_extract_u32(value).and_then(|v| self.delta_to_absolute_ns(v));
                    }
                    FlowEndDeltaMicroseconds => {
                        flow.time_flow_end_ns =
                            ipfix_extract_u32(value).and_then(|v| self.delta_to_absolute_ns(v));
                    }
                    SourceIpv6Address => {
                        if let IpfixFieldValue::Ipv6Address(addr) = value {
                            flow.src_addr = Some(IpAddr::V6(*addr));
                            flow.etype = Some(0x86dd);
                        }
                    }
                    DestinationIpv6Address => {
                        if let IpfixFieldValue::Ipv6Address(addr) = value {
                            flow.dst_addr = Some(IpAddr::V6(*addr));
                        }
                    }
                    SourceIpv6PrefixLength => flow.src_net = ipfix_extract_u8(value),
                    DestinationIpv6PrefixLength => flow.dst_net = ipfix_extract_u8(value),
                    FlowLabelIpv6 => flow.ipv6_flow_label = ipfix_extract_u32(value),
                    IcmpTypeCodeIpv4 => {
                        if let Some(v) = ipfix_extract_u16(value) {
                            flow.icmp_type = Some((v >> 8) as u8);
                            flow.icmp_code = Some((v & 0xff) as u8);
                        }
                    }
                    IcmpTypeIpv4 | IcmpTypeIpv6 => flow.icmp_type = ipfix_extract_u8(value),
                    IcmpCodeIpv4 | IcmpCodeIpv6 => flow.icmp_code = ipfix_extract_u8(value),
                    SamplingInterval | SamplingPacketInterval | SamplerRandomInterval => {
                        if self.sampling_rate.is_none() {
                            flow.sampling_rate = ipfix_extract_u32(value);
                        }
                    }
                    SrcVlan => flow.src_vlan = ipfix_extract_u16(value),
                    DstVlan => flow.dst_vlan = ipfix_extract_u16(value),
                    IpNextHopIpv6Address => {
                        if let IpfixFieldValue::Ipv6Address(addr) = value {
                            flow.next_hop = Some(IpAddr::V6(*addr));
                        }
                    }
                    BgpNextHopIpv6Address => {
                        if let IpfixFieldValue::Ipv6Address(addr) = value {
                            flow.bgp_next_hop = Some(IpAddr::V6(*addr));
                        }
                    }
                    MinimumTtl | MaximumTtl => flow.ip_ttl = ipfix_extract_u8(value),
                    FragmentIdentification => flow.fragment_id = ipfix_extract_u32(value),
                    SourceMacAddress | PostSourceMacAddress => {
                        if let IpfixFieldValue::MacAddress(mac) = value {
                            flow.src_mac = Some(*mac);
                        }
                    }
                    DestinationMacAddress | PostDestinationMacAddress => {
                        if let IpfixFieldValue::MacAddress(mac) = value {
                            flow.dst_mac = Some(*mac);
                        }
                    }
                    // PSAMP Packet Reports (RFC 5476 section 6.4)
                    SelectionSequenceId => {
                        flow.selection_sequence_id = ipfix_extract_u64_opt(value);
                    }
                    ObservationTimeSeconds
                    | ObservationTimeMilliseconds
                    | ObservationTimeMicroseconds
                    | ObservationTimeNanoseconds => {
                        // A Packet Report describes a single instant.
                        let ns = ipfix_extract_datetime_ns(value);
                        flow.time_flow_start_ns = ns;
                        flow.time_flow_end_ns = ns;
                    }
                    DataLinkFrameSize => flow.bytes = ipfix_extract_u64(value),
                    DataLinkFrameSection => {
                        if let IpfixFieldValue::OctetArray(bytes) = value {
                            flow.packets = 1;
                            // The section may be truncated; dataLinkFrameSize
                            // carries the original length when exported.
                            if flow.bytes == 0 {
                                flow.bytes = bytes.len() as u64;
                            }
                            if let Ok(sliced) = LaxSlicedPacket::from_ethernet(bytes) {
                                apply_sliced_packet(&mut flow, &sliced);
                            }
                        }
                    }
                    IpHeaderPacketSection => {
                        if let IpfixFieldValue::OctetArray(bytes) = value {
                            flow.packets = 1;
                            if flow.bytes == 0 {
                                flow.bytes = bytes.len() as u64;
                            }
                            if let Ok(sliced) = LaxSlicedPacket::from_ip(bytes) {
                                apply_sliced_packet(&mut flow, &sliced);
                            }
                        }
                    }
                    IpPayloadPacketSection | MplsLabelStackSection | MplsPayloadPacketSection => {
                        flow.packets = 1;
                    }
                    _ => {}
                }
            }
        }

        // A Packet Report describes exactly one packet, even when it carries
        // no packet section (Extended Packet Reports, RFC 5476 section 6.4.2).
        if flow.selection_sequence_id.is_some() && flow.packets == 0 {
            flow.packets = 1;
        }

        flow
    }
}

fn ipfix_extract_u8(value: &IpfixFieldValue) -> Option<u8> {
    match value {
        IpfixFieldValue::Unsigned8(v) => Some(*v),
        IpfixFieldValue::Unsigned16(v) => Some(*v as u8),
        IpfixFieldValue::Unsigned32(v) => Some(*v as u8),
        IpfixFieldValue::Unsigned64(v) => Some(*v as u8),
        _ => None,
    }
}

fn ipfix_extract_u16(value: &IpfixFieldValue) -> Option<u16> {
    match value {
        IpfixFieldValue::Unsigned8(v) => Some(*v as u16),
        IpfixFieldValue::Unsigned16(v) => Some(*v),
        IpfixFieldValue::Unsigned32(v) => Some(*v as u16),
        IpfixFieldValue::Unsigned64(v) => Some(*v as u16),
        _ => None,
    }
}

fn ipfix_extract_u32(value: &IpfixFieldValue) -> Option<u32> {
    match value {
        IpfixFieldValue::Unsigned8(v) => Some(*v as u32),
        IpfixFieldValue::Unsigned16(v) => Some(*v as u32),
        IpfixFieldValue::Unsigned32(v) => Some(*v),
        IpfixFieldValue::Unsigned64(v) => Some(*v as u32),
        _ => None,
    }
}

fn ipfix_extract_u64_opt(value: &IpfixFieldValue) -> Option<u64> {
    match value {
        IpfixFieldValue::Unsigned8(v) => Some(*v as u64),
        IpfixFieldValue::Unsigned16(v) => Some(*v as u64),
        IpfixFieldValue::Unsigned32(v) => Some(*v as u64),
        IpfixFieldValue::Unsigned64(v) => Some(*v),
        _ => None,
    }
}

fn ipfix_extract_u64(value: &IpfixFieldValue) -> u64 {
    match value {
        IpfixFieldValue::Unsigned8(v) => *v as u64,
        IpfixFieldValue::Unsigned16(v) => *v as u64,
        IpfixFieldValue::Unsigned32(v) => *v as u64,
        IpfixFieldValue::Unsigned64(v) => *v,
        _ => 0,
    }
}

fn ipfix_extract_datetime_ns(value: &IpfixFieldValue) -> Option<i64> {
    match value {
        IpfixFieldValue::DateTimeSeconds(dt)
        | IpfixFieldValue::DateTimeMilliseconds(dt)
        | IpfixFieldValue::DateTimeMicroseconds(dt)
        | IpfixFieldValue::DateTimeNanoseconds(dt) => dt.timestamp_nanos_opt(),
        _ => None,
    }
}

pub fn extract_ipfix_sampling_rate(record: &IpfixDataRecord) -> Option<u32> {
    let sampling_interval_id: u16 = InformationElement::SamplingInterval.into();
    let sampling_packet_interval_id: u16 = InformationElement::SamplingPacketInterval.into();
    let sampler_random_interval_id: u16 = InformationElement::SamplerRandomInterval.into();
    let selector_algorithm_id: u16 = InformationElement::SelectorAlgorithm.into();

    // A PSAMP Selector Report (RFC 5476) also carries samplingPacketInterval,
    // but with interval/space semantics rather than a flat 1-in-N rate; those
    // records are interpreted by the PSAMP cache instead.
    if record
        .0
        .iter()
        .any(|(field, _, _)| field.information_element_identifier == selector_algorithm_id)
    {
        return None;
    }

    for (field, _, value) in &record.0 {
        let field_type = &field.information_element_identifier;
        if *field_type == sampling_interval_id
            || *field_type == sampling_packet_interval_id
            || *field_type == sampler_random_interval_id
        {
            return ipfix_extract_u32(value);
        }
    }
    None
}

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice};

use crate::sflow_v5::parser::{
    AsPathType, ExpandedFlowSample, ExtendedGateway, ExtendedRouter, ExtendedSwitch,
    FlowRecordType, FlowSample, HeaderProtocol, SFlowV5, SampledHeader, SampledIpv4, SampledIpv6,
};

pub struct SFlowV5Context<'a> {
    pub header: &'a SFlowV5,
}

impl SFlowV5Context<'_> {
    pub fn convert_flow_sample(&self, sample: &FlowSample) -> CommonFlow {
        let mut flow = CommonFlow::new(FlowType::SflowV5);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = Some(self.header.agent_address);
        flow.sampling_rate = Some(sample.sampling_rate);
        flow.in_if = Some(sample.input);
        flow.out_if = Some(sample.output);

        for record in &sample.records {
            self.apply_flow_record(&mut flow, &record.data);
        }

        flow
    }

    pub fn convert_expanded_flow_sample(&self, sample: &ExpandedFlowSample) -> CommonFlow {
        let mut flow = CommonFlow::new(FlowType::SflowV5);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = Some(self.header.agent_address);
        flow.sampling_rate = Some(sample.sampling_rate);
        flow.in_if = Some(sample.input_if_value);
        flow.out_if = Some(sample.output_if_value);

        for record in &sample.records {
            self.apply_flow_record(&mut flow, &record.data);
        }

        flow
    }

    fn apply_flow_record(&self, flow: &mut CommonFlow, record_type: &FlowRecordType) {
        match record_type {
            FlowRecordType::SampledHeader(header) => {
                self.apply_sampled_header(flow, header);
            }
            FlowRecordType::SampledIpv4(ipv4) => {
                self.apply_sampled_ipv4(flow, ipv4);
            }
            FlowRecordType::SampledIpv6(ipv6) => {
                self.apply_sampled_ipv6(flow, ipv6);
            }
            FlowRecordType::ExtendedRouter(router) => {
                self.apply_extended_router(flow, router);
            }
            FlowRecordType::ExtendedSwitch(switch) => {
                self.apply_extended_switch(flow, switch);
            }
            FlowRecordType::ExtendedGateway(gateway) => {
                self.apply_extended_gateway(flow, gateway);
            }
            _ => {}
        }
    }

    fn apply_sampled_header(&self, flow: &mut CommonFlow, header: &SampledHeader) {
        flow.bytes = header.frame_length as u64;
        flow.packets = 1;

        match header.protocol {
            HeaderProtocol::EthernetIso8023 => {
                if let Ok(sliced) = LaxSlicedPacket::from_ethernet(&header.header) {
                    apply_sliced_packet(flow, &sliced);
                }
            }
            HeaderProtocol::Ipv4 => {
                if let Ok(sliced) = LaxSlicedPacket::from_ip(&header.header) {
                    flow.etype = Some(0x0800);
                    apply_sliced_packet(flow, &sliced);
                }
            }
            HeaderProtocol::Ipv6 => {
                if let Ok(sliced) = LaxSlicedPacket::from_ip(&header.header) {
                    flow.etype = Some(0x86dd);
                    apply_sliced_packet(flow, &sliced);
                }
            }
            _ => {}
        }
    }
}

/// Dissect a sliced packet header into the flow's link/network/transport
/// fields. Shared by sFlow sampled headers and PSAMP packet sections; lax
/// slicing is used because both are usually truncated below the packet's
/// declared length.
fn apply_sliced_packet(flow: &mut CommonFlow, sliced: &LaxSlicedPacket) {
    if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
        let header = eth.to_header();
        flow.src_mac = Some(MacAddr6::from(header.source));
        flow.dst_mac = Some(MacAddr6::from(header.destination));
        flow.etype = Some(header.ether_type.0);
    }

    match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4_slice)) => {
            let ipv4_header = ipv4_slice.header();
            flow.src_addr = Some(IpAddr::V4(ipv4_header.source_addr()));
            flow.dst_addr = Some(IpAddr::V4(ipv4_header.destination_addr()));
            flow.proto = Some(ipv4_header.protocol().0);
            flow.ip_tos = Some(ipv4_header.dcp().value());
            flow.ip_ttl = Some(ipv4_header.ttl());
            flow.fragment_id = Some(ipv4_header.identification() as u32);
            flow.fragment_offset = Some(ipv4_header.fragments_offset().value());
            if flow.etype.is_none() {
                flow.etype = Some(0x0800);
            }
        }
        Some(LaxNetSlice::Ipv6(ipv6_slice)) => {
            let ipv6_header = ipv6_slice.header();
            flow.src_addr = Some(IpAddr::V6(ipv6_header.source_addr()));
            flow.dst_addr = Some(IpAddr::V6(ipv6_header.destination_addr()));
            flow.proto = Some(ipv6_slice.payload().ip_number.0);
            flow.ip_ttl = Some(ipv6_header.hop_limit());
            flow.ipv6_flow_label = Some(ipv6_header.flow_label().value());
            if flow.etype.is_none() {
                flow.etype = Some(0x86dd);
            }
        }
        Some(LaxNetSlice::Arp(_)) | None => {}
    }

    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp_slice)) => {
            flow.src_port = Some(tcp_slice.source_port());
            flow.dst_port = Some(tcp_slice.destination_port());

            let header = tcp_slice.to_header();
            let mut flags: u16 = 0;
            if header.fin {
                flags |= 0x01;
            }
            if header.syn {
                flags |= 0x02;
            }
            if header.rst {
                flags |= 0x04;
            }
            if header.psh {
                flags |= 0x08;
            }
            if header.ack {
                flags |= 0x10;
            }
            if header.urg {
                flags |= 0x20;
            }
            if header.ece {
                flags |= 0x40;
            }
            if header.cwr {
                flags |= 0x80;
            }
            if header.ns {
                flags |= 0x100;
            }
            flow.tcp_flags = Some(flags);
        }
        Some(TransportSlice::Udp(udp_slice)) => {
            flow.src_port = Some(udp_slice.source_port());
            flow.dst_port = Some(udp_slice.destination_port());
        }
        Some(TransportSlice::Icmpv4(icmp_slice)) => {
            flow.icmp_type = Some(icmp_slice.type_u8());
            flow.icmp_code = Some(icmp_slice.code_u8());
        }
        Some(TransportSlice::Icmpv6(icmp_slice)) => {
            flow.icmp_type = Some(icmp_slice.type_u8());
            flow.icmp_code = Some(icmp_slice.code_u8());
        }
        _ => {}
    }
}

impl SFlowV5Context<'_> {
    fn apply_sampled_ipv4(&self, flow: &mut CommonFlow, ipv4: &SampledIpv4) {
        flow.src_addr = Some(IpAddr::V4(ipv4.src_ip));
        flow.dst_addr = Some(IpAddr::V4(ipv4.dst_ip));
        flow.etype = Some(0x0800);
        flow.proto = Some(ipv4.protocol as u8);
        flow.src_port = Some(ipv4.src_port as u16);
        flow.dst_port = Some(ipv4.dst_port as u16);
        flow.tcp_flags = Some(ipv4.tcp_flags as u16);
        flow.ip_tos = Some(ipv4.tos as u8);
        flow.bytes = ipv4.length as u64;
        flow.packets = 1;
    }

    fn apply_sampled_ipv6(&self, flow: &mut CommonFlow, ipv6: &SampledIpv6) {
        flow.src_addr = Some(IpAddr::V6(ipv6.src_ip));
        flow.dst_addr = Some(IpAddr::V6(ipv6.dst_ip));
        flow.etype = Some(0x86dd);
        flow.proto = Some(ipv6.protocol as u8);
        flow.src_port = Some(ipv6.src_port as u16);
        flow.dst_port = Some(ipv6.dst_port as u16);
        flow.tcp_flags = Some(ipv6.tcp_flags as u16);
        flow.bytes = ipv6.length as u64;
        flow.packets = 1;
    }

    fn apply_extended_router(&self, flow: &mut CommonFlow, router: &ExtendedRouter) {
        flow.next_hop = Some(router.nexthop);
        flow.src_net = Some(router.src_mask as u8);
        flow.dst_net = Some(router.dst_mask as u8);
    }

    fn apply_extended_switch(&self, flow: &mut CommonFlow, switch: &ExtendedSwitch) {
        flow.src_vlan = Some(switch.src_vlan as u16);
        flow.dst_vlan = Some(switch.dst_vlan as u16);
    }

    fn apply_extended_gateway(&self, flow: &mut CommonFlow, gateway: &ExtendedGateway) {
        flow.src_as = Some(gateway.src_as);
        flow.dst_as = match &gateway.dst_as_path {
            AsPathType::AsSequence(as_seq) => as_seq.last().copied(),
            _ => None,
        };
    }
}
