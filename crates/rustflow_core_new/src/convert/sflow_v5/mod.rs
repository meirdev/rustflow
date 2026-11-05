//! sFlow v5 flow samples as IPFIX records: each sample is one sampled
//! packet, described by the records the agent decoded and by what
//! dissecting its sampled header finds.
//!
//! Counter samples, drop notifications and samples of unknown formats
//! convert to no record.

use std::net::IpAddr;

use crate::convert::packet_section::{self, IPV4_ETHERNET_TYPE, IPV6_ETHERNET_TYPE, Layer};
use crate::convert::record::Fields;
use crate::convert::sampling::{Method, Sampling};
use crate::convert::{Protocol, Received, Record};
use crate::protocol::information_element::iana;
use crate::protocol::sflow_v5::{
    AsPathSegment, ExtendedGateway, ExtendedRouter, ExtendedSwitch, FlowRecord, FlowSample,
    HeaderProtocol, Interface, Packet, Sample, SampledEthernet, SampledHeader, SampledIpv4,
    SampledIpv6,
};
use crate::protocol::value::Value;

/// A compact interface value standing for the agent itself rather than an
/// interface. The expanded encoding defines no such value.
const INTERNAL_INTERFACE: u32 = 0x3fff_ffff;

/// Converts an sFlow v5 datagram's flow samples, adding a record of each to
/// `records`.
///
/// The agent's address is the `exporterIPv4Address` (or IPv6), and its
/// sub-agent ID the original observation domain, as the scope of the
/// datagrams' sequence numbers. The sampling rate is one packet in that
/// many, chosen at random as sFlow samples.
pub fn convert(packet: Packet, received: &Received, records: &mut impl Extend<Record>) {
    let header = &packet.header;
    let mut base = Fields::additions(received, Some(header.sub_agent_id));
    match header.agent_address {
        Some(IpAddr::V4(address)) => {
            base.push(iana::EXPORTER_IPV4_ADDRESS, Value::Ipv4Address(address));
        }
        Some(IpAddr::V6(address)) => {
            base.push(iana::EXPORTER_IPV6_ADDRESS, Value::Ipv6Address(address));
        }
        None => {}
    }

    let mut last_elements = None;
    records.extend(packet.samples.into_iter().filter_map(|sample| {
        let (sample, compact) = match &sample {
            Sample::Flow(sample) => (sample, true),
            Sample::ExpandedFlow(sample) => (sample, false),
            _ => return None,
        };
        let mut fields = flow_fields(sample, compact);
        let mut additions = base.clone();
        Sampling {
            rate: sample.sampling_rate.max(1),
            method: Some(Method::Random),
        }
        .add_to(&mut additions);
        fields.append(additions);
        Some(fields.into_record(
            Protocol::SflowV5,
            header.sequence_number,
            &mut last_elements,
        ))
    }));
}

fn flow_fields(sample: &FlowSample, compact: bool) -> Fields {
    let mut fields = Fields::default();
    if let Some(index) = if_index(sample.input, compact) {
        fields.add(iana::INGRESS_INTERFACE, Value::Unsigned32(index));
    }
    if let Some(index) = if_index(sample.output, compact) {
        fields.add(iana::EGRESS_INTERFACE, Value::Unsigned32(index));
    }
    for record in &sample.records {
        match record {
            FlowRecord::SampledHeader(header) => add_sampled_header(&mut fields, header),
            FlowRecord::SampledEthernet(ethernet) => add_sampled_ethernet(&mut fields, ethernet),
            FlowRecord::SampledIpv4(ipv4) => add_sampled_ipv4(&mut fields, ipv4),
            FlowRecord::SampledIpv6(ipv6) => add_sampled_ipv6(&mut fields, ipv6),
            FlowRecord::ExtendedSwitch(switch) => add_extended_switch(&mut fields, switch),
            FlowRecord::ExtendedGateway(gateway) => add_extended_gateway(&mut fields, gateway),
            _ => {}
        }
    }
    // Prefix lengths have an element for each address family, which only
    // the packet's addresses tell.
    for record in &sample.records {
        if let FlowRecord::ExtendedRouter(router) = record {
            add_extended_router(&mut fields, router);
        }
    }
    fields.add(iana::PACKET_DELTA_COUNT, Value::Unsigned64(1));
    fields
}

/// The ifIndex an interface names, if any. Only format 0 is an ifIndex,
/// with 0 for unknown; format 1 is a discard reason and 2 a count of output
/// interfaces.
fn if_index(interface: Interface, compact: bool) -> Option<u32> {
    let Interface { format, value } = interface;
    let internal = compact && value == INTERNAL_INTERFACE;
    (format == 0 && value != 0 && !internal).then_some(value)
}

/// The frame length counts the octets of the header's protocol: layer 2
/// octets but for a header that starts at the IP header.
fn add_sampled_header(fields: &mut Fields, header: &SampledHeader) {
    let length = Value::Unsigned64(header.frame_length.into());
    let layer = match header.protocol {
        HeaderProtocol::Ipv4 | HeaderProtocol::Ipv6 => {
            fields.add(iana::OCTET_DELTA_COUNT, length);
            Layer::Ip
        }
        HeaderProtocol::EthernetIso88023 => {
            fields.add(iana::LAYER2_OCTET_DELTA_COUNT, length);
            Layer::Ethernet
        }
        _ => {
            fields.add(iana::LAYER2_OCTET_DELTA_COUNT, length);
            return;
        }
    };
    if let Some(headers) = packet_section::headers(layer, &header.header) {
        packet_section::add(headers, &mut |element, value| fields.add(element, value));
    }
}

fn add_sampled_ethernet(fields: &mut Fields, ethernet: &SampledEthernet) {
    fields.add(
        iana::SOURCE_MAC_ADDRESS,
        Value::MacAddress(ethernet.src_mac),
    );
    fields.add(
        iana::DESTINATION_MAC_ADDRESS,
        Value::MacAddress(ethernet.dst_mac),
    );
    if let Ok(ethernet_type) = u16::try_from(ethernet.r#type) {
        fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(ethernet_type));
    }
    fields.add(
        iana::LAYER2_OCTET_DELTA_COUNT,
        Value::Unsigned64(ethernet.length.into()),
    );
}

fn add_sampled_ipv4(fields: &mut Fields, ipv4: &SampledIpv4) {
    fields.add(iana::SOURCE_IPV4_ADDRESS, Value::Ipv4Address(ipv4.src_ip));
    fields.add(
        iana::DESTINATION_IPV4_ADDRESS,
        Value::Ipv4Address(ipv4.dst_ip),
    );
    fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV4_ETHERNET_TYPE));
    add_sampled_ip(fields, ipv4.length, ipv4.protocol, ipv4.tos);
    add_ports(fields, ipv4.src_port, ipv4.dst_port, ipv4.tcp_flags);
}

fn add_sampled_ipv6(fields: &mut Fields, ipv6: &SampledIpv6) {
    fields.add(iana::SOURCE_IPV6_ADDRESS, Value::Ipv6Address(ipv6.src_ip));
    fields.add(
        iana::DESTINATION_IPV6_ADDRESS,
        Value::Ipv6Address(ipv6.dst_ip),
    );
    fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV6_ETHERNET_TYPE));
    add_sampled_ip(fields, ipv6.length, ipv6.protocol, ipv6.priority);
    add_ports(fields, ipv6.src_port, ipv6.dst_port, ipv6.tcp_flags);
}

/// sFlow carries these in 32 bits each; a value too large for its element
/// is left out.
fn add_sampled_ip(fields: &mut Fields, length: u32, protocol: u32, class_of_service: u32) {
    fields.add(iana::OCTET_DELTA_COUNT, Value::Unsigned64(length.into()));
    if let Ok(protocol) = u8::try_from(protocol) {
        fields.add(iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(protocol));
    }
    if let Ok(class_of_service) = u8::try_from(class_of_service) {
        fields.add(
            iana::IP_CLASS_OF_SERVICE,
            Value::Unsigned8(class_of_service),
        );
    }
}

fn add_ports(fields: &mut Fields, src_port: u32, dst_port: u32, tcp_flags: u32) {
    if let Ok(port) = u16::try_from(src_port) {
        fields.add(iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(port));
    }
    if let Ok(port) = u16::try_from(dst_port) {
        fields.add(iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(port));
    }
    if let Ok(flags) = u16::try_from(tcp_flags) {
        fields.add(iana::TCP_CONTROL_BITS, Value::Unsigned16(flags));
    }
}

/// An unknown VLAN is 0xffffffff, which no VLAN ID fits.
fn add_extended_switch(fields: &mut Fields, switch: &ExtendedSwitch) {
    if let Ok(vlan) = u16::try_from(switch.src_vlan) {
        fields.add(iana::VLAN_ID, Value::Unsigned16(vlan));
    }
    if let Ok(vlan) = u16::try_from(switch.dst_vlan) {
        fields.add(iana::POST_VLAN_ID, Value::Unsigned16(vlan));
    }
}

/// The destination AS is the last of the AS path, or 0 when the path ends
/// in an unordered AS set, as IANA defines `bgpDestinationAsNumber`.
fn add_extended_gateway(fields: &mut Fields, gateway: &ExtendedGateway) {
    match gateway.nexthop {
        Some(IpAddr::V4(address)) => {
            fields.add(iana::BGP_NEXT_HOP_IPV4_ADDRESS, Value::Ipv4Address(address));
        }
        Some(IpAddr::V6(address)) => {
            fields.add(iana::BGP_NEXT_HOP_IPV6_ADDRESS, Value::Ipv6Address(address));
        }
        None => {}
    }
    fields.add(
        iana::BGP_SOURCE_AS_NUMBER,
        Value::Unsigned32(gateway.src_as),
    );
    let dst_as = match gateway.dst_as_path.last() {
        Some(AsPathSegment::AsSequence(path)) => path.last().copied(),
        Some(AsPathSegment::AsSet(_)) => Some(0),
        None => None,
    };
    if let Some(dst_as) = dst_as {
        fields.add(iana::BGP_DESTINATION_AS_NUMBER, Value::Unsigned32(dst_as));
    }
}

fn add_extended_router(fields: &mut Fields, router: &ExtendedRouter) {
    match router.nexthop {
        Some(IpAddr::V4(address)) => {
            fields.add(iana::IP_NEXT_HOP_IPV4_ADDRESS, Value::Ipv4Address(address));
        }
        Some(IpAddr::V6(address)) => {
            fields.add(iana::IP_NEXT_HOP_IPV6_ADDRESS, Value::Ipv6Address(address));
        }
        None => {}
    }
    let (src_mask, dst_mask) = if fields.has(iana::SOURCE_IPV4_ADDRESS) {
        (
            iana::SOURCE_IPV4_PREFIX_LENGTH,
            iana::DESTINATION_IPV4_PREFIX_LENGTH,
        )
    } else if fields.has(iana::SOURCE_IPV6_ADDRESS) {
        (
            iana::SOURCE_IPV6_PREFIX_LENGTH,
            iana::DESTINATION_IPV6_PREFIX_LENGTH,
        )
    } else {
        return;
    };
    if let Ok(length) = u8::try_from(router.src_mask_len) {
        fields.add(src_mask, Value::Unsigned8(length));
    }
    if let Ok(length) = u8::try_from(router.dst_mask_len) {
        fields.add(dst_mask, Value::Unsigned8(length));
    }
}

#[cfg(test)]
mod tests;
