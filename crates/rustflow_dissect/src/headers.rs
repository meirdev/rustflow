//! The headers a packet has, after peeling, as plain values.

use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanHeader};

use crate::peel::{Peeled, first_fragment_transport};

/// What dissecting a packet found: the innermost IP packet, which names the
/// flow, its transport header, and the innermost link layer that has a link
/// header, which may be a tunnel's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Headers {
    pub link: Option<Link>,
    pub net: Option<Net>,
    pub transport: Option<Transport>,
}

/// An Ethernet header and its VLAN tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    /// The outer tag's VLAN ID, if tagged.
    pub vlan: Option<u16>,
    /// The inner tag's VLAN ID, if tagged twice.
    pub customer_vlan: Option<u16>,
    /// The ethertype after the tags.
    pub ether_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    /// DSCP and ECN, as the header's second byte.
    pub class_of_service: u8,
    pub ttl: u8,
    pub identification: u16,
    /// In eight-byte units.
    pub fragment_offset: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    /// The protocol after the extension headers.
    pub next_header: u8,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub flow_label: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        source_port: u16,
        destination_port: u16,
        /// NS, CWR, ECE, URG, ACK, PSH, RST, SYN and FIN, from bit 8 down
        /// to bit 0.
        flags: u16,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
    },
    Icmpv4 {
        r#type: u8,
        code: u8,
    },
    Icmpv6 {
        r#type: u8,
        code: u8,
    },
}

impl Headers {
    pub(crate) fn of(peeled: &Peeled<'_>) -> Self {
        let packet = &peeled.packet;
        Self {
            link: link(peeled.link.as_ref().unwrap_or(packet)),
            net: net(packet),
            transport: transport(packet),
        }
    }
}

fn link(sliced: &LaxSlicedPacket<'_>) -> Option<Link> {
    let LinkSlice::Ethernet2(ethernet) = sliced.link.as_ref()? else {
        return None;
    };
    let (vlan, customer_vlan, ether_type) = match sliced.vlan().map(|vlan| vlan.to_header()) {
        Some(VlanHeader::Single(tag)) => (Some(tag.vlan_id.value()), None, tag.ether_type.0),
        Some(VlanHeader::Double(tags)) => (
            Some(tags.outer.vlan_id.value()),
            Some(tags.inner.vlan_id.value()),
            tags.inner.ether_type.0,
        ),
        None => (None, None, ethernet.ether_type().0),
    };
    Some(Link {
        source: ethernet.source(),
        destination: ethernet.destination(),
        vlan,
        customer_vlan,
        ether_type,
    })
}

fn net(sliced: &LaxSlicedPacket<'_>) -> Option<Net> {
    match sliced.net.as_ref()? {
        LaxNetSlice::Ipv4(ipv4) => {
            let header = ipv4.header();
            Some(Net::Ipv4(Ipv4 {
                source: header.source_addr(),
                destination: header.destination_addr(),
                protocol: header.protocol().0,
                class_of_service: (header.dcp().value() << 2) | header.ecn().value(),
                ttl: header.ttl(),
                identification: header.identification(),
                fragment_offset: header.fragments_offset().value(),
            }))
        }
        LaxNetSlice::Ipv6(ipv6) => {
            let header = ipv6.header();
            Some(Net::Ipv6(Ipv6 {
                source: header.source_addr(),
                destination: header.destination_addr(),
                next_header: ipv6.payload().ip_number.0,
                traffic_class: header.traffic_class(),
                hop_limit: header.hop_limit(),
                flow_label: header.flow_label().value(),
            }))
        }
        LaxNetSlice::Arp(_) => None,
    }
}

/// The transport header, which a first fragment still carries.
fn transport(sliced: &LaxSlicedPacket<'_>) -> Option<Transport> {
    let transport = sliced
        .transport
        .clone()
        .or_else(|| first_fragment_transport(sliced))?;
    Some(match transport {
        TransportSlice::Tcp(tcp) => {
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
            Transport::Tcp {
                source_port: tcp.source_port(),
                destination_port: tcp.destination_port(),
                flags: flags
                    .into_iter()
                    .fold(0, |bits, set| bits << 1 | u16::from(set)),
            }
        }
        TransportSlice::Udp(udp) => Transport::Udp {
            source_port: udp.source_port(),
            destination_port: udp.destination_port(),
        },
        TransportSlice::Icmpv4(icmp) => Transport::Icmpv4 {
            r#type: icmp.type_u8(),
            code: icmp.code_u8(),
        },
        TransportSlice::Icmpv6(icmp) => Transport::Icmpv6 {
            r#type: icmp.type_u8(),
            code: icmp.code_u8(),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use etherparse::{IpNumber, PacketBuilder, VlanId};

    use super::*;
    use crate::test_packets::{INNER, OUTER, fragment, gre, ipv4, ipv4_udp};
    use crate::{ethernet, ip};

    #[test]
    fn a_tagged_tcp_frame_gives_every_layer() {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .single_vlan(VlanId::try_new(20).unwrap())
            .ipv4(INNER, OUTER, 64)
            .tcp(1234, 80, 0, 1024)
            .syn()
            .write(&mut frame, &[0; 8])
            .unwrap();
        let headers = ethernet(&frame).unwrap();

        assert_eq!(
            headers.link,
            Some(Link {
                source: [2; 6],
                destination: [4; 6],
                vlan: Some(20),
                customer_vlan: None,
                ether_type: 0x0800,
            })
        );
        let Some(Net::Ipv4(ipv4)) = headers.net else {
            panic!("expected IPv4");
        };
        assert_eq!(ipv4.source, Ipv4Addr::from(INNER));
        assert_eq!(ipv4.protocol, 6);
        assert_eq!(ipv4.ttl, 64);
        assert_eq!(
            headers.transport,
            Some(Transport::Tcp {
                source_port: 1234,
                destination_port: 80,
                flags: 0x02,
            })
        );
    }

    #[test]
    fn a_tunnelled_packet_gives_the_inner_ip_and_the_outer_link() {
        let inner = ipv4_udp(INNER, 53, b"x");
        let frame = crate::test_packets::ethernet(
            0x0800,
            &ipv4(OUTER, IpNumber::GRE, &gre(0x0800, &inner)),
        );
        let headers = ethernet(&frame).unwrap();

        let Some(Net::Ipv4(ipv4)) = headers.net else {
            panic!("expected IPv4");
        };
        assert_eq!(ipv4.source, Ipv4Addr::from(INNER));
        assert!(matches!(
            headers.transport,
            Some(Transport::Udp {
                destination_port: 53,
                ..
            })
        ));
        assert_eq!(headers.link.unwrap().ether_type, 0x0800);
    }

    #[test]
    fn a_first_fragment_still_gives_its_transport() {
        let whole = ipv4_udp(INNER, 53, &[0; 32]);
        assert!(matches!(
            ip(&fragment(&whole, 0)).unwrap().transport,
            Some(Transport::Udp { .. })
        ));
        assert_eq!(ip(&fragment(&whole, 4)).unwrap().transport, None);
    }
}
