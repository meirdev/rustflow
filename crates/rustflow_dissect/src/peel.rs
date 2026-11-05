use etherparse::{
    Icmpv4Slice, Icmpv6Slice, IpNumber, Ipv6ExtensionSlice, LaxNetSlice, LaxSlicedPacket,
    LenSource, TcpSlice, TransportSlice, UdpSlice,
};

use crate::tunnel::{Inner, encapsulated};

/// The deepest packet successfully parsed within the tunnel depth limit.
pub(crate) struct Peeled<'a> {
    /// The enclosing packet retained for its link-layer metadata when
    /// `packet` has no link header. `None` if `packet` has its own link
    /// header or no enclosing link layer was available.
    pub link: Option<LaxSlicedPacket<'a>>,
    /// The last successfully parsed packet, which may still be encapsulated.
    pub packet: LaxSlicedPacket<'a>,
}

/// Maximum number of decapsulation steps; an MPLS label stack is one step.
const MAX_TUNNEL_DEPTH: u8 = 4;

/// Peels a frame that starts at its Ethernet header.
///
/// Inner Ethernet frames replace the enclosing link-layer metadata. Inner
/// IP packets retain it in [`Peeled::link`]. Peeling stops at an unsupported
/// or malformed encapsulation, or when the tunnel depth limit is reached.
/// Returns `None` if the initial Ethernet frame cannot be parsed.
pub(crate) fn peel_ethernet(frame: &[u8]) -> Option<Peeled<'_>> {
    LaxSlicedPacket::from_ethernet(frame).ok().map(peel)
}

/// Like [`peel_ethernet`], but starts at an IPv4 or IPv6 header.
pub(crate) fn peel_ip(packet: &[u8]) -> Option<Peeled<'_>> {
    LaxSlicedPacket::from_ip(packet).ok().map(peel)
}

fn peel(sliced: LaxSlicedPacket<'_>) -> Peeled<'_> {
    peel_with(sliced, false)
}

/// Like [`peel`], but only descends through an enclosing packet that is
/// whole: a truncated outer IP packet or a UDP header whose length does
/// not match its bytes stops the peeling there, so the caller's checks
/// see the bad layer rather than something inside it.
pub(crate) fn peel_strict(sliced: LaxSlicedPacket<'_>) -> Peeled<'_> {
    peel_with(sliced, true)
}

fn peel_with(sliced: LaxSlicedPacket<'_>, require_complete: bool) -> Peeled<'_> {
    let mut link = None;
    let mut packet = sliced;
    for _ in 0..MAX_TUNNEL_DEPTH {
        if require_complete && !is_complete(&packet) {
            break;
        }
        match encapsulated(&packet) {
            Some(Inner::Ethernet(frame)) => match LaxSlicedPacket::from_ethernet(frame) {
                Ok(inner) => {
                    link = None;
                    packet = inner;
                }
                Err(_) => break,
            },
            Some(Inner::Ip(bytes)) => match LaxSlicedPacket::from_ip(bytes) {
                Ok(inner) => {
                    if link.is_none() && packet.link.is_some() {
                        link = Some(packet);
                    }
                    packet = inner;
                }
                Err(_) => break,
            },
            None => break,
        }
    }
    Peeled { link, packet }
}

/// The transport header of a first fragment. etherparse leaves the
/// transport unsliced for any fragment, but the first one still carries
/// the header, and the ports are what a flow is keyed on.
pub(crate) fn first_fragment_transport<'a>(
    sliced: &LaxSlicedPacket<'a>,
) -> Option<TransportSlice<'a>> {
    let payload = match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4)) if ipv4.header().fragments_offset().value() == 0 => {
            ipv4.payload()
        }
        Some(LaxNetSlice::Ipv6(ipv6)) if ipv6_fragment_offset(ipv6.extensions().clone()) == 0 => {
            ipv6.payload()
        }
        _ => return None,
    };
    if !payload.fragmented {
        return None;
    }
    let bytes = payload.payload;
    match payload.ip_number {
        IpNumber::TCP => TcpSlice::from_slice(bytes).ok().map(TransportSlice::Tcp),
        IpNumber::UDP => UdpSlice::from_slice_lax(bytes)
            .ok()
            .map(TransportSlice::Udp),
        IpNumber::ICMP => Icmpv4Slice::from_slice(bytes)
            .ok()
            .map(TransportSlice::Icmpv4),
        IpNumber::IPV6_ICMP => Icmpv6Slice::from_slice(bytes)
            .ok()
            .map(TransportSlice::Icmpv6),
        _ => None,
    }
}

fn ipv6_fragment_offset(extensions: etherparse::Ipv6ExtensionsSlice<'_>) -> u16 {
    extensions
        .into_iter()
        .find_map(|ext| match ext {
            Ipv6ExtensionSlice::Fragment(fragment) => Some(fragment.fragment_offset().value()),
            _ => None,
        })
        .unwrap_or(0)
}

/// Whether the IP packet is all there: with a length field that holds, not
/// truncated, not a fragment, and with a UDP length that matches the bytes
/// when the transport is UDP. A packet with no IP layer yet, such as a frame
/// carrying an MPLS stack, has nothing to check.
///
/// Where the IP length field does not hold, etherparse takes the slice's
/// length instead: for an IPv4 total length shorter than the header, and
/// for an IPv6 payload length of 0, which only a jumbogram may have and
/// etherparse does not read the jumbogram's length.
pub(crate) fn is_complete(sliced: &LaxSlicedPacket<'_>) -> bool {
    let Some(ip_payload) = sliced.ip_payload() else {
        return true;
    };
    if ip_payload.len_source == LenSource::Slice || ip_payload.incomplete || ip_payload.fragmented {
        return false;
    }
    match &sliced.transport {
        Some(TransportSlice::Udp(udp)) => udp.payload().len() + 8 == usize::from(udp.length()),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use etherparse::{PacketBuilder, VlanId};

    use super::*;
    use crate::test_packets::*;

    #[test]
    fn a_plain_frame_is_its_own_packet() {
        let frame = ethernet(0x0800, &ipv4_udp(INNER, 53, b"x"));
        let peeled = peel_ethernet(&frame).unwrap();
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::from(INNER)));
        assert!(peeled.link.is_none());
        assert!(matches!(
            peeled.packet.transport,
            Some(TransportSlice::Udp(_))
        ));
    }

    #[test]
    fn vlan_tags_are_passed_through() {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .single_vlan(VlanId::try_new(100).unwrap())
            .ipv4(INNER, OUTER, 64)
            .udp(1000, 53)
            .write(&mut frame, b"x")
            .unwrap();
        let peeled = peel_ethernet(&frame).unwrap();
        assert_eq!(peeled.packet.link_exts.len(), 1);
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::from(INNER)));
    }

    #[test]
    fn an_inner_ip_packet_keeps_the_outer_link_layer() {
        let tunnel = ipv4(
            OUTER,
            IpNumber::GRE,
            &gre(0x0800, &ipv4_udp(INNER, 53, b"x")),
        );
        let frame = ethernet(0x0800, &tunnel);
        let peeled = peel_ethernet(&frame).unwrap();
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::from(INNER)));
        let link = peeled.link.expect("the outer frame, for its link layer");
        assert_eq!(source(&link), Some(Ipv4Addr::from(OUTER)));
    }

    #[test]
    fn an_inner_ethernet_frame_replaces_the_link_layer() {
        let inner = ethernet(0x0800, &ipv4_udp(INNER, 53, b"x"));
        let frame = ethernet(0x0800, &ipv4(OUTER, IpNumber::GRE, &gre(0x6558, &inner)));
        let peeled = peel_ethernet(&frame).unwrap();
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::from(INNER)));
        assert!(peeled.packet.link.is_some());
        assert!(peeled.link.is_none());
    }

    #[test]
    fn peeling_stops_after_four_tunnels() {
        let mut packet = ipv4_udp([10, 0, 0, 5], 53, b"x");
        for layer in (0..5).rev() {
            packet = ipv4([10, 0, 0, layer], IpNumber::GRE, &gre(0x0800, &packet));
        }
        let peeled = peel_ip(&packet).unwrap();
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::new(10, 0, 0, 4)));
    }

    #[test]
    fn lax_peeling_goes_through_a_length_field_that_does_not_hold() {
        let tunnel = ipv4(
            OUTER,
            IpNumber::GRE,
            &gre(0x0800, &ipv4_udp(INNER, 53, b"x")),
        );
        let packet = zero_total_length(&tunnel);
        let peeled = peel_ip(&packet).unwrap();
        assert_eq!(source(&peeled.packet), Some(Ipv4Addr::from(INNER)));
    }

    fn transport(packet: &[u8]) -> Option<TransportSlice<'_>> {
        first_fragment_transport(&LaxSlicedPacket::from_ip(packet).unwrap())
    }

    #[test]
    fn a_first_fragment_still_gives_its_transport() {
        let whole = ipv4_udp(INNER, 53, &[0; 32]);
        let first = fragment(&whole, 0);
        let later = fragment(&whole, 4);
        assert!(
            LaxSlicedPacket::from_ip(&first)
                .unwrap()
                .transport
                .is_none()
        );
        assert!(
            matches!(transport(&first), Some(TransportSlice::Udp(udp)) if udp.destination_port() == 53)
        );
        assert!(transport(&later).is_none());
        assert!(transport(&whole).is_none());
    }
}
