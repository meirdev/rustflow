//! The fields a sampled packet yields, found by dissecting its first bytes
//! through any tunnels to the innermost IP packet, whose addresses describe
//! the flow. The link layer is the innermost one that has a link header.
//!
//! sFlow carries those bytes in a flow sample's sampled header; IPFIX and
//! NetFlow v9 in a PSAMP packet section (RFC 5477).

use crate::dissect::{Headers, Link, Net, Transport};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::value::Value;

pub(crate) const IPV4_ETHERNET_TYPE: u16 = 0x0800;
pub(crate) const IPV6_ETHERNET_TYPE: u16 = 0x86dd;

/// IEEE 802.3 Ethernet, in `dataLinkFrameType`.
const ETHERNET_FRAME_TYPE: u64 = 1;

/// The header a packet section starts at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    Ethernet,
    Ip,
}

/// The section among `fields`, by position, if it starts at a header that
/// can be dissected: a `dataLinkFrameSection` of an Ethernet frame, or else
/// an `ipHeaderPacketSection`, neither cut short of its start by a
/// `sectionOffset`.
pub(crate) fn find<'a>(
    fields: impl Iterator<Item = (ElementId, &'a Value)>,
) -> Option<(usize, Layer)> {
    let (mut frame, mut packet) = (None, None);
    let mut ethernet = true;
    for (index, (element, value)) in fields.enumerate() {
        match (element, value) {
            (iana::DATA_LINK_FRAME_SECTION, Value::OctetArray(_)) => frame = Some(index),
            (iana::IP_HEADER_PACKET_SECTION, Value::OctetArray(_)) => packet = Some(index),
            (iana::DATA_LINK_FRAME_TYPE, _) => {
                ethernet = value.as_u64() == Some(ETHERNET_FRAME_TYPE);
            }
            (iana::SECTION_OFFSET, _) if value.as_u64() != Some(0) => return None,
            _ => {}
        }
    }
    frame
        .filter(|_| ethernet)
        .map(|index| (index, Layer::Ethernet))
        .or_else(|| packet.map(|index| (index, Layer::Ip)))
}

/// The headers of a section, peeled through any tunnels.
pub(crate) fn headers(layer: Layer, bytes: &[u8]) -> Option<Headers> {
    match layer {
        Layer::Ethernet => crate::dissect::ethernet(bytes),
        Layer::Ip => crate::dissect::ip(bytes),
    }
}

/// Gives `add` each field the headers yield, an element more than once
/// where layers repeat one: the network layer comes first, so that the
/// `ethernetType` a caller keeping the first of each gets is the one of
/// the IP packet giving the addresses, though a tunnel such as GRE or MPLS
/// sat under it in the frame.
pub(crate) fn add(headers: Headers, add: &mut impl FnMut(ElementId, Value)) {
    let Headers {
        link,
        net,
        transport,
    } = headers;
    if let Some(net) = net {
        add_net(net, add);
    }
    if let Some(transport) = transport {
        add_transport(transport, add);
    }
    if let Some(link) = link {
        add_link(link, add);
    }
}

fn add_net(net: Net, add: &mut impl FnMut(ElementId, Value)) {
    match net {
        Net::Ipv4(ipv4) => {
            add(iana::SOURCE_IPV4_ADDRESS, Value::Ipv4Address(ipv4.source));
            add(
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address(ipv4.destination),
            );
            add(iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(ipv4.protocol));
            add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8(ipv4.class_of_service),
            );
            add(iana::IP_TTL, Value::Unsigned8(ipv4.ttl));
            add(
                iana::FRAGMENT_IDENTIFICATION,
                Value::Unsigned32(ipv4.identification.into()),
            );
            add(
                iana::FRAGMENT_OFFSET,
                Value::Unsigned16(ipv4.fragment_offset),
            );
            add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV4_ETHERNET_TYPE));
        }
        Net::Ipv6(ipv6) => {
            add(iana::SOURCE_IPV6_ADDRESS, Value::Ipv6Address(ipv6.source));
            add(
                iana::DESTINATION_IPV6_ADDRESS,
                Value::Ipv6Address(ipv6.destination),
            );
            add(
                iana::PROTOCOL_IDENTIFIER,
                Value::Unsigned8(ipv6.next_header),
            );
            add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8(ipv6.traffic_class),
            );
            add(iana::IP_TTL, Value::Unsigned8(ipv6.hop_limit));
            add(iana::FLOW_LABEL_IPV6, Value::Unsigned32(ipv6.flow_label));
            add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV6_ETHERNET_TYPE));
        }
    }
}

fn add_transport(transport: Transport, add: &mut impl FnMut(ElementId, Value)) {
    match transport {
        Transport::Tcp {
            source_port,
            destination_port,
            flags,
        } => {
            add(iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(source_port));
            add(
                iana::DESTINATION_TRANSPORT_PORT,
                Value::Unsigned16(destination_port),
            );
            add(iana::TCP_CONTROL_BITS, Value::Unsigned16(flags));
        }
        Transport::Udp {
            source_port,
            destination_port,
        } => {
            add(iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(source_port));
            add(
                iana::DESTINATION_TRANSPORT_PORT,
                Value::Unsigned16(destination_port),
            );
        }
        Transport::Icmpv4 { r#type, code } => {
            add(iana::ICMP_TYPE_IPV4, Value::Unsigned8(r#type));
            add(iana::ICMP_CODE_IPV4, Value::Unsigned8(code));
        }
        Transport::Icmpv6 { r#type, code } => {
            add(iana::ICMP_TYPE_IPV6, Value::Unsigned8(r#type));
            add(iana::ICMP_CODE_IPV6, Value::Unsigned8(code));
        }
    }
}

/// A frame's tags are `dot1qVlanId`, and the inner one of two
/// `dot1qCustomerVlanId`; `vlanId` is left to an extended switch record,
/// which knows the VLANs of the interfaces.
fn add_link(link: Link, add: &mut impl FnMut(ElementId, Value)) {
    if let Some(vlan) = link.vlan {
        add(iana::DOT1Q_VLAN_ID, Value::Unsigned16(vlan));
    }
    if let Some(vlan) = link.customer_vlan {
        add(iana::DOT1Q_CUSTOMER_VLAN_ID, Value::Unsigned16(vlan));
    }
    add(iana::SOURCE_MAC_ADDRESS, Value::MacAddress(link.source));
    add(
        iana::DESTINATION_MAC_ADDRESS,
        Value::MacAddress(link.destination),
    );
    add(iana::ETHERNET_TYPE, Value::Unsigned16(link.ether_type));
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use etherparse::PacketBuilder;

    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn frame() -> Vec<u8> {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv4(SRC.octets(), [198, 51, 100, 1], 64)
            .udp(1234, 53)
            .write(&mut frame, &[])
            .unwrap();
        frame
    }

    /// The fields as a caller keeps them: the first of each element.
    fn dissected(layer: Layer, bytes: &[u8]) -> Vec<(ElementId, Value)> {
        let mut fields: Vec<(ElementId, Value)> = Vec::new();
        add(headers(layer, bytes).unwrap(), &mut |element, value| {
            if !fields.iter().any(|(known, _)| *known == element) {
                fields.push((element, value));
            }
        });
        fields
    }

    #[test]
    fn a_frame_and_the_packet_in_it_yield_the_same_network_fields() {
        let frame = frame();
        let by_frame = dissected(Layer::Ethernet, &frame);
        let by_packet = dissected(Layer::Ip, &frame[14..]);
        assert!(by_frame.contains(&(iana::SOURCE_IPV4_ADDRESS, Value::Ipv4Address(SRC))));
        assert!(by_frame.contains(&(iana::SOURCE_MAC_ADDRESS, Value::MacAddress([2; 6]))));
        assert!(!by_packet.contains(&(iana::SOURCE_MAC_ADDRESS, Value::MacAddress([2; 6]))));
        let network = |fields: &[(ElementId, Value)]| {
            fields
                .iter()
                .filter(|(element, _)| {
                    *element != iana::SOURCE_MAC_ADDRESS
                        && *element != iana::DESTINATION_MAC_ADDRESS
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(network(&by_frame), network(&by_packet));
    }

    #[test]
    fn a_record_carries_a_section_in_one_of_two_elements() {
        let frame = frame();
        let section = |fields: &[(ElementId, Value)]| {
            find(fields.iter().map(|(element, value)| (*element, value)))
        };
        let bytes = Value::OctetArray(frame.clone());
        assert_eq!(
            section(&[(iana::DATA_LINK_FRAME_SECTION, bytes.clone())]),
            Some((0, Layer::Ethernet))
        );
        assert_eq!(
            section(&[(iana::IP_HEADER_PACKET_SECTION, bytes.clone())]),
            Some((0, Layer::Ip))
        );
        assert_eq!(
            section(&[
                (iana::IP_HEADER_PACKET_SECTION, bytes.clone()),
                (iana::DATA_LINK_FRAME_SECTION, bytes.clone()),
            ]),
            Some((1, Layer::Ethernet))
        );
        assert_eq!(
            section(&[
                (iana::DATA_LINK_FRAME_TYPE, Value::Unsigned16(2)),
                (iana::DATA_LINK_FRAME_SECTION, bytes.clone()),
            ]),
            None
        );
        assert_eq!(
            section(&[
                (iana::SECTION_OFFSET, Value::Unsigned16(4)),
                (iana::DATA_LINK_FRAME_SECTION, bytes.clone()),
            ]),
            None
        );
        assert_eq!(
            section(&[(iana::OCTET_DELTA_COUNT, Value::Unsigned64(1))]),
            None
        );
    }
}
