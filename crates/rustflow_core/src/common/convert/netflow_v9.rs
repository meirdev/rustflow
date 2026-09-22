use std::net::IpAddr;

use crate::common::InformationElement;
use crate::common::common_flow::{CommonFlow, FlowType};
use crate::netflow_v9::parser::{
    DataRecord as V9DataRecord, FieldValue as V9FieldValue, Header as V9Header,
};

pub struct NetFlowV9Context<'a> {
    pub header: &'a V9Header,
    pub sampler_address: Option<IpAddr>,
    pub sampling_rate: Option<u32>,
}

impl NetFlowV9Context<'_> {
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

        for (field_type, _, value) in record.iter() {
            if let Some(ie) = InformationElement::from_id(field_type) {
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
                    IcmpTypeCodeIpv4 | IcmpTypeCodeIpv6 => {
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
    for (field_type, _, value) in record.iter() {
        if field_type == sampling_interval_id
            || field_type == sampling_packet_interval_id
            || field_type == sampler_random_interval_id
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
