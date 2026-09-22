use std::net::IpAddr;

use crate::common::InformationElement;
use crate::common::common_flow::{CommonFlow, FlowType};
use crate::common::convert::packet::{apply_ethernet_frame, apply_ip_packet};
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

        // RFC 7133 packet sections (Juniper inline monitoring exports one
        // record per sampled packet with `dataLinkFrameSection`). The
        // header goes in first so that the elements the record states
        // explicitly overwrite it, whatever their order in the template.
        let section = packet_section(record);
        match section {
            Some(PacketSection::Frame(bytes)) => apply_ethernet_frame(&mut flow, bytes),
            Some(PacketSection::Ip(bytes)) => apply_ip_packet(&mut flow, bytes),
            None => {}
        }
        let mut frame_size: Option<u64> = None;

        for (field, _, value) in record.iter() {
            let field_type = &field.information_element_identifier;
            if let Some(ie) = InformationElement::from_id(*field_type) {
                match ie {
                    OctetDeltaCount => flow.bytes = ipfix_extract_u64(value),
                    PacketDeltaCount => flow.packets = ipfix_extract_u64(value),
                    DataLinkFrameSize => frame_size = Some(ipfix_extract_u64(value)),
                    DataLinkFrameSection | IpHeaderPacketSection => {}
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
                    IcmpTypeCodeIpv4 | IcmpTypeCodeIpv6 => {
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
                    _ => {}
                }
            }
        }

        // A record without counters is one packet of `dataLinkFrameSize`
        // bytes, or of the section's length when the size is absent.
        if let Some(section) = section {
            if flow.bytes == 0 {
                flow.bytes = frame_size.unwrap_or(section.len() as u64);
            }
            if flow.packets == 0 {
                flow.packets = 1;
            }
        }

        flow
    }
}

/// The header bytes a record carries, if any; a frame section wins over an
/// IP header section.
enum PacketSection<'a> {
    Frame(&'a [u8]),
    Ip(&'a [u8]),
}

impl PacketSection<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Frame(bytes) | Self::Ip(bytes) => bytes.len(),
        }
    }
}

fn packet_section(record: &IpfixDataRecord) -> Option<PacketSection<'_>> {
    let mut ip = None;
    for (field, _, value) in record.iter() {
        let IpfixFieldValue::OctetArray(bytes) = value else {
            continue;
        };
        match InformationElement::from_id(field.information_element_identifier) {
            Some(InformationElement::DataLinkFrameSection) => {
                return Some(PacketSection::Frame(bytes.as_slice()));
            }
            Some(InformationElement::IpHeaderPacketSection) => ip = Some(bytes.as_slice()),
            _ => {}
        }
    }
    ip.map(PacketSection::Ip)
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
    for (field, _, value) in record.iter() {
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
