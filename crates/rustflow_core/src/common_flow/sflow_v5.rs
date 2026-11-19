use std::net::{IpAddr, Ipv4Addr};

use super::packet::dissect;
use super::{CommonFlow, FlowType};
use crate::net::{ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, Protocol};
use crate::sflow_v5::{
    AsPathSegment, ExtendedGateway, ExtendedRouter, ExtendedSwitch, FlowRecord, FlowSample,
    HeaderProtocol, Interface, Packet, Sample, SampledEthernet, SampledHeader, SampledIpv4,
    SampledIpv6,
};

/// An interface given by its ifIndex.
const INTERFACE_FORMAT_INDEX: u32 = 0;
/// The ifIndex standing for the agent itself, in a compact sample only; the
/// expanded encoding defines no such value.
const INTERFACE_INTERNAL: u32 = 0x3fff_ffff;

pub fn from_sflow_v5(
    packet: &Packet,
    time_received_ns: i64,
) -> impl Iterator<Item = CommonFlow> + '_ {
    let header = &packet.header;
    // An agent address of the unknown type carries no address.
    let sampler_address = header
        .agent_address
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let flow_samples = packet.samples.iter().filter_map(|sample| match sample {
        Sample::Flow(sample) => Some((sample, Encoding::Compact)),
        Sample::ExpandedFlow(sample) => Some((sample, Encoding::Expanded)),
        _ => None,
    });
    flow_samples.map(move |(sample, encoding)| {
        let flow = CommonFlow::new(
            FlowType::SflowV5,
            time_received_ns,
            sampler_address,
            header.sequence_number,
        );
        flow_of(flow, sample, encoding)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Compact,
    Expanded,
}

fn flow_of(flow: CommonFlow, sample: &FlowSample, encoding: Encoding) -> CommonFlow {
    let mut flow = CommonFlow {
        sampling_rate: (sample.sampling_rate != 0).then_some(sample.sampling_rate),
        in_if: interface(sample.input, encoding),
        out_if: interface(sample.output, encoding),
        packets: Some(1),
        ..flow
    };
    for record in &sample.records {
        match record {
            FlowRecord::SampledHeader(header) => add_header(&mut flow, header),
            FlowRecord::SampledEthernet(ethernet) => add_ethernet(&mut flow, ethernet),
            FlowRecord::SampledIpv4(ipv4) => add_ipv4(&mut flow, ipv4),
            FlowRecord::SampledIpv6(ipv6) => add_ipv6(&mut flow, ipv6),
            FlowRecord::ExtendedSwitch(switch) => add_switch(&mut flow, switch),
            FlowRecord::ExtendedRouter(router) => add_router(&mut flow, router),
            FlowRecord::ExtendedGateway(gateway) => add_gateway(&mut flow, gateway),
            _ => {}
        }
    }
    flow
}

/// The ifIndex of an interface, unless it is unknown (0), the agent itself,
/// or not an ifIndex at all (a drop reason, a count of interfaces).
fn interface(Interface { format, value }: Interface, encoding: Encoding) -> Option<u32> {
    let internal = encoding == Encoding::Compact && value == INTERFACE_INTERNAL;
    let known = format == INTERFACE_FORMAT_INDEX && value != 0 && !internal;
    known.then_some(value)
}

fn add_header(flow: &mut CommonFlow, sampled: &SampledHeader) {
    flow.bytes = Some(sampled.frame_length.into());
    let protocol = match sampled.protocol {
        HeaderProtocol::EthernetIso88023 => Protocol::Ethernet,
        HeaderProtocol::Ipv4 => Protocol::Ipv4,
        HeaderProtocol::Ipv6 => Protocol::Ipv6,
        _ => return,
    };
    // The header is clipped; what was read before the end still counts.
    dissect(flow, protocol, &mut sampled.header.as_slice());
}

fn add_ethernet(flow: &mut CommonFlow, ethernet: &SampledEthernet) {
    flow.bytes.get_or_insert(ethernet.length.into());
    flow.src_mac.get_or_insert(ethernet.src_mac);
    flow.dst_mac.get_or_insert(ethernet.dst_mac);
    fill(&mut flow.etype, ethernet.r#type);
}

fn add_ipv4(flow: &mut CommonFlow, ipv4: &SampledIpv4) {
    flow.bytes.get_or_insert(ipv4.length.into());
    flow.etype.get_or_insert(ETHER_TYPE_IPV4);
    flow.src_addr.get_or_insert(ipv4.src_ip.into());
    flow.dst_addr.get_or_insert(ipv4.dst_ip.into());
    fill(&mut flow.proto, ipv4.protocol);
    fill(&mut flow.src_port, ipv4.src_port);
    fill(&mut flow.dst_port, ipv4.dst_port);
    fill(&mut flow.tcp_flags, ipv4.tcp_flags);
    fill(&mut flow.ip_tos, ipv4.tos);
}

fn add_ipv6(flow: &mut CommonFlow, ipv6: &SampledIpv6) {
    flow.bytes.get_or_insert(ipv6.length.into());
    flow.etype.get_or_insert(ETHER_TYPE_IPV6);
    flow.src_addr.get_or_insert(ipv6.src_ip.into());
    flow.dst_addr.get_or_insert(ipv6.dst_ip.into());
    fill(&mut flow.proto, ipv6.protocol);
    fill(&mut flow.src_port, ipv6.src_port);
    fill(&mut flow.dst_port, ipv6.dst_port);
    fill(&mut flow.tcp_flags, ipv6.tcp_flags);
}

fn add_switch(flow: &mut CommonFlow, switch: &ExtendedSwitch) {
    // 0xFFFFFFFF when the VLAN is unknown, which does not fit.
    flow.src_vlan = u16::try_from(switch.src_vlan).ok().or(flow.src_vlan);
    flow.dst_vlan = u16::try_from(switch.dst_vlan).ok().or(flow.dst_vlan);
}

fn add_router(flow: &mut CommonFlow, router: &ExtendedRouter) {
    flow.next_hop = router.nexthop.or(flow.next_hop);
    flow.src_net = u8::try_from(router.src_mask_len).ok().or(flow.src_net);
    flow.dst_net = u8::try_from(router.dst_mask_len).ok().or(flow.dst_net);
}

fn add_gateway(flow: &mut CommonFlow, gateway: &ExtendedGateway) {
    flow.bgp_next_hop = gateway.nexthop.or(flow.bgp_next_hop);
    flow.src_as = Some(gateway.src_as);
    // The destination is the last AS on the path to it. An AS_SET, from
    // aggregated routes, is unordered and has no last AS.
    let last_as = gateway
        .dst_as_path
        .last()
        .and_then(|segment| match segment {
            AsPathSegment::AsSequence(ases) => ases.last().copied(),
            AsPathSegment::AsSet(_) => None,
        });
    flow.dst_as = last_as.or(flow.dst_as);
}

fn fill<T: TryFrom<u32>>(field: &mut Option<T>, number: u32) {
    if field.is_none() {
        *field = T::try_from(number).ok();
    }
}
