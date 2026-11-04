//! The fields a sampled packet yields, found by dissecting its first bytes
//! through any tunnels to the innermost IP packet, whose addresses describe
//! the flow. The link layer is the innermost one that has a link header.
//!
//! sFlow carries those bytes in a flow sample's sampled header; IPFIX and
//! NetFlow v9 in a PSAMP packet section (RFC 5477).

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanHeader};
use rustflow_dissect::{first_fragment_transport, peel_ethernet, peel_ip};
use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::value::Value;

pub(crate) const IPV4_ETHERNET_TYPE: u16 = 0x0800;
pub(crate) const IPV6_ETHERNET_TYPE: u16 = 0x86dd;

/// IEEE 802.3 Ethernet, in `dataLinkFrameType`.
const ETHERNET_FRAME_TYPE: u64 = 1;

/// The first bytes of a packet, and the header they start at.
pub(crate) enum Section<'a> {
    Ethernet(&'a [u8]),
    Ip(&'a [u8]),
}

impl<'a> Section<'a> {
    /// The section a record carries, if it starts at a header that can be
    /// dissected: a `dataLinkFrameSection` of an Ethernet frame, or else an
    /// `ipHeaderPacketSection`, neither cut short of its start by a
    /// `sectionOffset`.
    pub(crate) fn of_record(fields: impl Iterator<Item = (ElementId, &'a Value)>) -> Option<Self> {
        let (mut frame, mut packet) = (None, None);
        let mut ethernet = true;
        for (element, value) in fields {
            match (element, value) {
                (iana::DATA_LINK_FRAME_SECTION, Value::OctetArray(bytes)) => frame = Some(bytes),
                (iana::IP_HEADER_PACKET_SECTION, Value::OctetArray(bytes)) => packet = Some(bytes),
                (iana::DATA_LINK_FRAME_TYPE, _) => {
                    ethernet = value.as_u64() == Some(ETHERNET_FRAME_TYPE);
                }
                (iana::SECTION_OFFSET, _) if value.as_u64() != Some(0) => return None,
                _ => {}
            }
        }
        frame
            .filter(|_| ethernet)
            .map(|bytes| Self::Ethernet(bytes))
            .or_else(|| packet.map(|bytes| Self::Ip(bytes)))
    }
}

/// Gives `add` each field the section yields, an element more than once
/// where layers repeat one: the network layer comes first, so that the
/// `ethernetType` a caller keeping the first of each gets is the one of
/// the IP packet giving the addresses, though a tunnel such as GRE or MPLS
/// sat under it in the frame.
pub(crate) fn dissect(section: Section<'_>, add: &mut impl FnMut(ElementId, Value)) {
    let peeled = match section {
        Section::Ethernet(frame) => peel_ethernet(frame),
        Section::Ip(packet) => peel_ip(packet),
    };
    if let Some(peeled) = peeled {
        add_net(&peeled.packet, add);
        add_transport(&peeled.packet, add);
        add_link(peeled.link.as_ref().unwrap_or(&peeled.packet), add);
    }
}

fn add_net(sliced: &LaxSlicedPacket, add: &mut impl FnMut(ElementId, Value)) {
    match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            add(
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address(header.source_addr()),
            );
            add(
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address(header.destination_addr()),
            );
            add(
                iana::PROTOCOL_IDENTIFIER,
                Value::Unsigned8(header.protocol().0),
            );
            add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8((header.dcp().value() << 2) | header.ecn().value()),
            );
            add(iana::IP_TTL, Value::Unsigned8(header.ttl()));
            add(
                iana::FRAGMENT_IDENTIFICATION,
                Value::Unsigned32(header.identification().into()),
            );
            add(
                iana::FRAGMENT_OFFSET,
                Value::Unsigned16(header.fragments_offset().value()),
            );
            add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV4_ETHERNET_TYPE));
        }
        Some(LaxNetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            add(
                iana::SOURCE_IPV6_ADDRESS,
                Value::Ipv6Address(header.source_addr()),
            );
            add(
                iana::DESTINATION_IPV6_ADDRESS,
                Value::Ipv6Address(header.destination_addr()),
            );
            add(
                iana::PROTOCOL_IDENTIFIER,
                Value::Unsigned8(ipv6.payload().ip_number.0),
            );
            add(
                iana::IP_CLASS_OF_SERVICE,
                Value::Unsigned8(header.traffic_class()),
            );
            add(iana::IP_TTL, Value::Unsigned8(header.hop_limit()));
            add(
                iana::FLOW_LABEL_IPV6,
                Value::Unsigned32(header.flow_label().value()),
            );
            add(iana::ETHERNET_TYPE, Value::Unsigned16(IPV6_ETHERNET_TYPE));
        }
        _ => {}
    }
}

fn add_transport(sliced: &LaxSlicedPacket, add: &mut impl FnMut(ElementId, Value)) {
    let transport = sliced
        .transport
        .clone()
        .or_else(|| first_fragment_transport(sliced));
    match transport {
        Some(TransportSlice::Tcp(tcp)) => {
            add(
                iana::SOURCE_TRANSPORT_PORT,
                Value::Unsigned16(tcp.source_port()),
            );
            add(
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
            add(iana::TCP_CONTROL_BITS, Value::Unsigned16(bits));
        }
        Some(TransportSlice::Udp(udp)) => {
            add(
                iana::SOURCE_TRANSPORT_PORT,
                Value::Unsigned16(udp.source_port()),
            );
            add(
                iana::DESTINATION_TRANSPORT_PORT,
                Value::Unsigned16(udp.destination_port()),
            );
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            add(iana::ICMP_TYPE_IPV4, Value::Unsigned8(icmp.type_u8()));
            add(iana::ICMP_CODE_IPV4, Value::Unsigned8(icmp.code_u8()));
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            add(iana::ICMP_TYPE_IPV6, Value::Unsigned8(icmp.type_u8()));
            add(iana::ICMP_CODE_IPV6, Value::Unsigned8(icmp.code_u8()));
        }
        _ => {}
    }
}

/// A frame's tags are `dot1qVlanId`, and the inner one of two
/// `dot1qCustomerVlanId`; `vlanId` is left to an extended switch record,
/// which knows the VLANs of the interfaces.
fn add_link(sliced: &LaxSlicedPacket, add: &mut impl FnMut(ElementId, Value)) {
    match sliced.vlan().map(|vlan| vlan.to_header()) {
        Some(VlanHeader::Single(tag)) => {
            add(iana::DOT1Q_VLAN_ID, Value::Unsigned16(tag.vlan_id.value()));
            add(iana::ETHERNET_TYPE, Value::Unsigned16(tag.ether_type.0));
        }
        Some(VlanHeader::Double(tags)) => {
            add(
                iana::DOT1Q_VLAN_ID,
                Value::Unsigned16(tags.outer.vlan_id.value()),
            );
            add(
                iana::DOT1Q_CUSTOMER_VLAN_ID,
                Value::Unsigned16(tags.inner.vlan_id.value()),
            );
            add(
                iana::ETHERNET_TYPE,
                Value::Unsigned16(tags.inner.ether_type.0),
            );
        }
        None => {}
    }
    if let Some(LinkSlice::Ethernet2(ethernet)) = &sliced.link {
        add(
            iana::SOURCE_MAC_ADDRESS,
            Value::MacAddress(ethernet.source()),
        );
        add(
            iana::DESTINATION_MAC_ADDRESS,
            Value::MacAddress(ethernet.destination()),
        );
        add(
            iana::ETHERNET_TYPE,
            Value::Unsigned16(ethernet.ether_type().0),
        );
    }
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
    fn dissected(section: Section<'_>) -> Vec<(ElementId, Value)> {
        let mut fields: Vec<(ElementId, Value)> = Vec::new();
        dissect(section, &mut |element, value| {
            if !fields.iter().any(|(known, _)| *known == element) {
                fields.push((element, value));
            }
        });
        fields
    }

    #[test]
    fn a_frame_and_the_packet_in_it_yield_the_same_network_fields() {
        let frame = frame();
        let by_frame = dissected(Section::Ethernet(&frame));
        let by_packet = dissected(Section::Ip(&frame[14..]));
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
            Section::of_record(fields.iter().map(|(element, value)| (*element, value)))
                .map(|section| matches!(section, Section::Ethernet(_)))
        };
        let bytes = Value::OctetArray(frame.clone());
        assert_eq!(
            section(&[(iana::DATA_LINK_FRAME_SECTION, bytes.clone())]),
            Some(true)
        );
        assert_eq!(
            section(&[(iana::IP_HEADER_PACKET_SECTION, bytes.clone())]),
            Some(false)
        );
        assert_eq!(
            section(&[
                (iana::IP_HEADER_PACKET_SECTION, bytes.clone()),
                (iana::DATA_LINK_FRAME_SECTION, bytes.clone()),
            ]),
            Some(true)
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
