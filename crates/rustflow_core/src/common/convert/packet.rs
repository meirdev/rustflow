use std::net::IpAddr;

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanHeader};
use macaddr::MacAddr6;

use crate::common::common_flow::CommonFlow;
use crate::common::packet::{Peeled, first_fragment_transport, peel_ethernet, peel_ip};

pub fn apply_ethernet_frame(flow: &mut CommonFlow, frame: &[u8]) {
    if let Some(peeled) = peel_ethernet(frame) {
        apply(flow, &peeled);
    }
}

pub fn apply_ip_packet(flow: &mut CommonFlow, packet: &[u8]) {
    if let Some(peeled) = peel_ip(packet) {
        apply(flow, &peeled);
    }
}

fn apply(flow: &mut CommonFlow, peeled: &Peeled) {
    apply_link(flow, peeled.link.as_ref().unwrap_or(&peeled.packet));
    apply_net_transport(flow, &peeled.packet);
}

/// The Ethernet header and VLAN tags. A VLAN already on the flow is kept:
/// an sFlow extended switch record knows the VLAN better than the frame's
/// tag does, whichever order the records arrive in.
fn apply_link(flow: &mut CommonFlow, sliced: &LaxSlicedPacket) {
    if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
        let header = eth.to_header();
        flow.src_mac = Some(MacAddr6::from(header.source));
        flow.dst_mac = Some(MacAddr6::from(header.destination));
        flow.etype = Some(header.ether_type.0);
    }
    if let Some(vlan) = sliced.vlan() {
        let inner = match vlan.to_header() {
            VlanHeader::Single(h) => h,
            VlanHeader::Double(h) => h.inner,
        };
        flow.etype = Some(inner.ether_type.0);
        if flow.src_vlan.is_none() {
            flow.src_vlan = Some(inner.vlan_id.value());
        }
    }
}

fn apply_net_transport(flow: &mut CommonFlow, sliced: &LaxSlicedPacket) {
    match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4_slice)) => {
            let ipv4_header = ipv4_slice.header();
            flow.src_addr = Some(IpAddr::V4(ipv4_header.source_addr()));
            flow.dst_addr = Some(IpAddr::V4(ipv4_header.destination_addr()));
            flow.proto = Some(ipv4_header.protocol().0);
            flow.ip_tos = Some((ipv4_header.dcp().value() << 2) | ipv4_header.ecn().value());
            flow.ip_ttl = Some(ipv4_header.ttl());
            flow.fragment_id = Some(ipv4_header.identification() as u32);
            flow.fragment_offset = Some(ipv4_header.fragments_offset().value());
            if flow.etype.is_none() {
                flow.etype = Some(EtherType::IPV4.0);
            }
        }
        Some(LaxNetSlice::Ipv6(ipv6_slice)) => {
            let ipv6_header = ipv6_slice.header();
            flow.src_addr = Some(IpAddr::V6(ipv6_header.source_addr()));
            flow.dst_addr = Some(IpAddr::V6(ipv6_header.destination_addr()));
            flow.proto = Some(ipv6_slice.payload().ip_number.0);
            flow.ip_tos = Some(ipv6_header.traffic_class());
            flow.ip_ttl = Some(ipv6_header.hop_limit());
            flow.ipv6_flow_label = Some(ipv6_header.flow_label().value());
            if flow.etype.is_none() {
                flow.etype = Some(EtherType::IPV6.0);
            }
        }
        Some(LaxNetSlice::Arp(_)) | None => {}
    }

    let transport = sliced.transport.clone().or_else(|| first_fragment_transport(sliced));
    match &transport {
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
