//! The fields of a sampled packet found by dissecting its header, through
//! any tunnels to the innermost IP packet, whose addresses describe the
//! flow. The link layer is the innermost one that has a link header.

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanHeader};
use rustflow_dissect::{Peeled, first_fragment_transport, peel_ethernet, peel_ip};
use rustflow_protocol::information_element::iana;
use rustflow_protocol::value::Value;

use super::{Fields, IPV4_ETHERNET_TYPE, IPV6_ETHERNET_TYPE};

pub(super) fn add_ethernet(fields: &mut Fields, frame: &[u8]) {
    if let Some(peeled) = peel_ethernet(frame) {
        add(fields, &peeled);
    }
}

pub(super) fn add_ip(fields: &mut Fields, packet: &[u8]) {
    if let Some(peeled) = peel_ip(packet) {
        add(fields, &peeled);
    }
}

/// The network layer comes first, so that `ethernetType` is the one of the
/// IP packet giving the addresses, though a tunnel such as GRE or MPLS sat
/// under it in the frame.
fn add(fields: &mut Fields, peeled: &Peeled) {
    add_net(fields, &peeled.packet);
    add_transport(fields, &peeled.packet);
    add_link(fields, peeled.link.as_ref().unwrap_or(&peeled.packet));
}

fn add_net(fields: &mut Fields, sliced: &LaxSlicedPacket) {
    match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            fields.add(
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address(header.source_addr()),
            );
            fields.add(
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address(header.destination_addr()),
            );
            fields.add(
                iana::PROTOCOL_IDENTIFIER,
                Value::Unsigned8(header.protocol().0),
            );
            fields.add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8((header.dcp().value() << 2) | header.ecn().value()),
            );
            fields.add(iana::IP_TTL, Value::Unsigned8(header.ttl()));
            fields.add(
                iana::FRAGMENT_IDENTIFICATION,
                Value::Unsigned32(header.identification().into()),
            );
            fields.add(
                iana::FRAGMENT_OFFSET,
                Value::Unsigned16(header.fragments_offset().value()),
            );
            fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV4_ETHERNET_TYPE));
        }
        Some(LaxNetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            fields.add(
                iana::SOURCE_IPV6_ADDRESS,
                Value::Ipv6Address(header.source_addr()),
            );
            fields.add(
                iana::DESTINATION_IPV6_ADDRESS,
                Value::Ipv6Address(header.destination_addr()),
            );
            fields.add(
                iana::PROTOCOL_IDENTIFIER,
                Value::Unsigned8(ipv6.payload().ip_number.0),
            );
            fields.add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8(header.traffic_class()),
            );
            fields.add(iana::IP_TTL, Value::Unsigned8(header.hop_limit()));
            fields.add(
                iana::FLOW_LABEL_IPV6,
                Value::Unsigned32(header.flow_label().value()),
            );
            fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV6_ETHERNET_TYPE));
        }
        _ => {}
    }
}

fn add_transport(fields: &mut Fields, sliced: &LaxSlicedPacket) {
    let transport = sliced
        .transport
        .clone()
        .or_else(|| first_fragment_transport(sliced));
    match transport {
        Some(TransportSlice::Tcp(tcp)) => {
            fields.add(
                iana::SOURCE_TRANSPORT_PORT,
                Value::Unsigned16(tcp.source_port()),
            );
            fields.add(
                iana::DESTINATION_TRANSPORT_PORT,
                Value::Unsigned16(tcp.destination_port()),
            );
            let flags = [
                tcp.ns(),
                tcp.cwr(),
                tcp.ece(),
                tcp.urg(),
                tcp.ack(),
                tcp.psh(),
                tcp.rst(),
                tcp.syn(),
                tcp.fin(),
            ];
            let bits = flags
                .into_iter()
                .fold(0, |bits, set| bits << 1 | u16::from(set));
            fields.add(iana::TCP_CONTROL_BITS, Value::Unsigned16(bits));
        }
        Some(TransportSlice::Udp(udp)) => {
            fields.add(
                iana::SOURCE_TRANSPORT_PORT,
                Value::Unsigned16(udp.source_port()),
            );
            fields.add(
                iana::DESTINATION_TRANSPORT_PORT,
                Value::Unsigned16(udp.destination_port()),
            );
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            fields.add(iana::ICMP_TYPE_IPV4, Value::Unsigned8(icmp.type_u8()));
            fields.add(iana::ICMP_CODE_IPV4, Value::Unsigned8(icmp.code_u8()));
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            fields.add(iana::ICMP_TYPE_IPV6, Value::Unsigned8(icmp.type_u8()));
            fields.add(iana::ICMP_CODE_IPV6, Value::Unsigned8(icmp.code_u8()));
        }
        _ => {}
    }
}

/// A frame's tags are `dot1qVlanId`, and the inner one of two
/// `dot1qCustomerVlanId`; `vlanId` is left to an extended switch record,
/// which knows the VLANs of the interfaces.
fn add_link(fields: &mut Fields, sliced: &LaxSlicedPacket) {
    match sliced.vlan().map(|vlan| vlan.to_header()) {
        Some(VlanHeader::Single(tag)) => {
            fields.add(iana::DOT1Q_VLAN_ID, Value::Unsigned16(tag.vlan_id.value()));
            fields.add(iana::ETHERNET_TYPE, Value::Unsigned16(tag.ether_type.0));
        }
        Some(VlanHeader::Double(tags)) => {
            fields.add(
                iana::DOT1Q_VLAN_ID,
                Value::Unsigned16(tags.outer.vlan_id.value()),
            );
            fields.add(
                iana::DOT1Q_CUSTOMER_VLAN_ID,
                Value::Unsigned16(tags.inner.vlan_id.value()),
            );
            fields.add(
                iana::ETHERNET_TYPE,
                Value::Unsigned16(tags.inner.ether_type.0),
            );
        }
        None => {}
    }
    if let Some(LinkSlice::Ethernet2(ethernet)) = &sliced.link {
        fields.add(
            iana::SOURCE_MAC_ADDRESS,
            Value::MacAddress(ethernet.source()),
        );
        fields.add(
            iana::DESTINATION_MAC_ADDRESS,
            Value::MacAddress(ethernet.destination()),
        );
        fields.add(
            iana::ETHERNET_TYPE,
            Value::Unsigned16(ethernet.ether_type().0),
        );
    }
}
