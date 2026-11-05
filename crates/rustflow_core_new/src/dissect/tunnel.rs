use etherparse::{EtherType, IpNumber, LaxNetSlice, LaxSlicedPacket, TransportSlice};

/// What a recognised encapsulation carries.
pub(crate) enum Inner<'a> {
    Ethernet(&'a [u8]),
    Ip(&'a [u8]),
}

const MPLS_UNICAST: EtherType = EtherType(0x8847);
const MPLS_MULTICAST: EtherType = EtherType(0x8848);
/// Transparent Ethernet bridging, the GRE and Geneve protocol type for an
/// inner Ethernet frame.
const TRANSPARENT_ETHERNET_BRIDGING: EtherType = EtherType(0x6558);
const ERSPAN_I_II: EtherType = EtherType(0x88be);
const ERSPAN_III: EtherType = EtherType(0x22eb);
const UDP_PORT_VXLAN: u16 = 4789;
const UDP_PORT_GENEVE: u16 = 6081;

pub(crate) fn encapsulated<'a>(sliced: &LaxSlicedPacket<'a>) -> Option<Inner<'a>> {
    // Check after any link-layer extensions, such as VLAN tags, because
    // etherparse leaves the MPLS label stack in the Ethernet payload.
    if let Some(payload) = sliced.ether_payload()
        && matches!(payload.ether_type, MPLS_UNICAST | MPLS_MULTICAST)
    {
        return mpls_inner(payload.payload);
    }

    let ip_payload = sliced.ip_payload()?;
    // A fragment carries a slice of some payload, not a header, whatever
    // its bytes happen to look like.
    if ip_payload.fragmented {
        return None;
    }
    if ip_payload.ip_number == IpNumber::GRE {
        return gre_inner(ip_payload.payload);
    }
    if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
        return match udp.destination_port() {
            UDP_PORT_VXLAN => vxlan_inner(udp.payload()),
            UDP_PORT_GENEVE => geneve_inner(udp.payload()),
            _ => None,
        };
    }
    None
}

/// Skips the MPLS label stack and guesses the payload type from its first
/// nibble: 4 or 6 means IP, 0 means a four-byte pseudowire control word
/// followed by Ethernet, and any other value means Ethernet directly.
/// Ethernet destination addresses can have the same leading nibbles, so
/// each reading is tried in order of likelihood and the first one that
/// slices to a network layer wins.
fn mpls_inner(mut bytes: &[u8]) -> Option<Inner<'_>> {
    loop {
        let (label, rest) = bytes.split_first_chunk::<4>()?;
        bytes = rest;
        if label[2] & 0x01 != 0 {
            break;
        }
    }
    let readings: [Option<Inner<'_>>; 2] = match bytes.first()? >> 4 {
        4 | 6 => [Some(Inner::Ip(bytes)), Some(Inner::Ethernet(bytes))],
        0 => [
            bytes.get(4..).map(Inner::Ethernet),
            Some(Inner::Ethernet(bytes)),
        ],
        _ => [Some(Inner::Ethernet(bytes)), None],
    };
    readings.into_iter().flatten().find(plausible)
}

/// Whether bytes read as `inner` decode to something with a network layer,
/// or to another MPLS stack. An IPv4 reading must also carry a correct
/// header checksum, which a MAC address mistaken for a header will not.
fn plausible(inner: &Inner<'_>) -> bool {
    match inner {
        Inner::Ip(bytes) => LaxSlicedPacket::from_ip(bytes).is_ok_and(|s| match &s.net {
            Some(LaxNetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                header.to_header().calc_header_checksum() == header.header_checksum()
            }
            Some(LaxNetSlice::Ipv6(_)) => true,
            _ => false,
        }),
        Inner::Ethernet(frame) => LaxSlicedPacket::from_ethernet(frame).is_ok_and(|s| {
            s.net.is_some()
                || s.ether_payload()
                    .is_some_and(|p| matches!(p.ether_type, MPLS_UNICAST | MPLS_MULTICAST))
        }),
    }
}

/// RFC 2784 and 2890 GRE, plus the ERSPAN headers Cisco puts behind it.
fn gre_inner(bytes: &[u8]) -> Option<Inner<'_>> {
    let (fixed, _) = bytes.split_first_chunk::<4>()?;
    let flags = u16::from_be_bytes([fixed[0], fixed[1]]);
    let protocol = EtherType(u16::from_be_bytes([fixed[2], fixed[3]]));
    // Only GRE version 0 is supported, and RFC 2784 section 2.3 requires
    // rejecting the RFC 1701 routing fields that the R flag announces.
    if flags & 0x0007 != 0 || flags & 0x4000 != 0 {
        return None;
    }
    let mut offset = 4;
    if flags & 0x8000 != 0 {
        offset += 4; // checksum and reserved
    }
    if flags & 0x2000 != 0 {
        offset += 4; // key
    }
    let has_sequence = flags & 0x1000 != 0;
    if has_sequence {
        offset += 4;
    }
    let payload = bytes.get(offset..)?;
    match protocol {
        EtherType::IPV4 | EtherType::IPV6 => Some(Inner::Ip(payload)),
        TRANSPARENT_ETHERNET_BRIDGING => Some(Inner::Ethernet(payload)),
        MPLS_UNICAST | MPLS_MULTICAST => mpls_inner(payload),
        // The GRE sequence-number flag distinguishes ERSPAN type II
        // (8-byte header) from type I (no ERSPAN header).
        ERSPAN_I_II if has_sequence => Some(Inner::Ethernet(payload.get(8..)?)),
        ERSPAN_I_II => Some(Inner::Ethernet(payload)),
        // Type III: 12-byte header, plus an 8-byte platform subheader
        // when its O bit is set.
        ERSPAN_III => {
            let header = payload.get(..12)?;
            let skip = if header[11] & 0x01 != 0 { 20 } else { 12 };
            Some(Inner::Ethernet(payload.get(skip..)?))
        }
        _ => None,
    }
}

/// RFC 7348: an 8-byte header whose only mandatory bit is the VNI flag.
fn vxlan_inner(payload: &[u8]) -> Option<Inner<'_>> {
    let (header, frame) = payload.split_first_chunk::<8>()?;
    (header[0] & 0x08 != 0).then_some(Inner::Ethernet(frame))
}

/// RFC 8926: an 8-byte header with a length field for the options that
/// follow it, and a protocol type saying what comes after them.
fn geneve_inner(payload: &[u8]) -> Option<Inner<'_>> {
    let (header, _) = payload.split_first_chunk::<8>()?;
    if header[0] >> 6 != 0 {
        return None;
    }
    let options_len = usize::from(header[0] & 0x3f) * 4;
    let protocol = EtherType(u16::from_be_bytes([header[2], header[3]]));
    let inner = payload.get(8 + options_len..)?;
    match protocol {
        TRANSPARENT_ETHERNET_BRIDGING => Some(Inner::Ethernet(inner)),
        EtherType::IPV4 | EtherType::IPV6 => Some(Inner::Ip(inner)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::dissect::peel_ip;
    use crate::dissect::test_packets::*;

    /// The source of the packet `packet` peels down to.
    fn peeled_source(packet: &[u8]) -> Option<Ipv4Addr> {
        source(&peel_ip(packet).unwrap().packet)
    }

    fn inner() -> Vec<u8> {
        ipv4_udp(INNER, 53, b"x")
    }

    fn inner_frame() -> Vec<u8> {
        ethernet(0x0800, &inner())
    }

    const INNER_ADDRESS: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 0, 2, 1));
    const OUTER_ADDRESS: Option<Ipv4Addr> = Some(Ipv4Addr::new(10, 0, 0, 1));

    fn over_gre(gre: &[u8]) -> Vec<u8> {
        ipv4(OUTER, IpNumber::GRE, gre)
    }

    #[test]
    fn gre_carries_ip_ethernet_and_mpls() {
        assert_eq!(
            peeled_source(&over_gre(&gre(0x0800, &inner()))),
            INNER_ADDRESS
        );
        assert_eq!(
            peeled_source(&over_gre(&gre(0x6558, &inner_frame()))),
            INNER_ADDRESS
        );
        assert_eq!(
            peeled_source(&over_gre(&gre(0x8847, &mpls(&inner())))),
            INNER_ADDRESS
        );
    }

    #[test]
    fn gre_optional_fields_are_skipped() {
        // Checksum, key and sequence number, four bytes each.
        let header = [&[0xb0, 0x00, 0x08, 0x00][..], &[0; 12]].concat();
        let packet = over_gre(&[header, inner()].concat());
        assert_eq!(peeled_source(&packet), INNER_ADDRESS);
    }

    #[test]
    fn gre_with_routing_or_another_version_is_not_peeled() {
        for flags in [[0x40, 0x00], [0x00, 0x01]] {
            let packet = over_gre(&[&flags[..], &[0x08, 0x00], &inner()].concat());
            assert_eq!(peeled_source(&packet), OUTER_ADDRESS, "flags {flags:?}");
        }
    }

    #[test]
    fn erspan_headers_are_skipped() {
        let type_i = gre(0x88be, &inner_frame());
        // Type II: the GRE sequence number, then an 8-byte ERSPAN header.
        let type_ii = [
            &[0x10, 0x00, 0x88, 0xbe][..],
            &[0; 4],
            &[0; 8],
            &inner_frame(),
        ]
        .concat();
        // Type III: a 12-byte header, then an 8-byte platform subheader when
        // its O bit is set.
        let type_iii = gre(0x22eb, &[&[0; 12][..], &inner_frame()].concat());
        let mut with_platform = [0; 20];
        with_platform[11] = 0x01;
        let type_iii_platform = gre(0x22eb, &[&with_platform[..], &inner_frame()].concat());
        for gre in [type_i, type_ii, type_iii, type_iii_platform] {
            assert_eq!(peeled_source(&over_gre(&gre)), INNER_ADDRESS);
        }
    }

    #[test]
    fn vxlan_needs_its_vni_flag() {
        let vxlan = |flags| [&[flags, 0, 0, 0, 0, 0, 1, 0][..], &inner_frame()].concat();
        let packet = |flags| ipv4_udp(OUTER, 4789, &vxlan(flags));
        assert_eq!(peeled_source(&packet(0x08)), INNER_ADDRESS);
        assert_eq!(peeled_source(&packet(0x00)), OUTER_ADDRESS);
    }

    #[test]
    fn geneve_options_are_skipped_and_its_version_checked() {
        // Version and options length in words, flags, protocol, VNI.
        let geneve = |first, protocol: u16, payload: &[u8]| {
            let header = [&[first, 0][..], &protocol.to_be_bytes(), &[0, 0, 1, 0]].concat();
            ipv4_udp(
                OUTER,
                6081,
                &[header, vec![0; 4], payload.to_vec()].concat(),
            )
        };
        assert_eq!(
            peeled_source(&geneve(0x01, 0x6558, &inner_frame())),
            INNER_ADDRESS
        );
        assert_eq!(
            peeled_source(&geneve(0x01, 0x0800, &inner())),
            INNER_ADDRESS
        );
        assert_eq!(
            peeled_source(&geneve(0x41, 0x0800, &inner())),
            OUTER_ADDRESS
        );
    }

    #[test]
    fn an_mpls_stack_is_read_to_its_bottom() {
        let stack = [&[0x00, 0x01, 0x00, 0x40][..], &mpls(&inner())].concat();
        let frame = ethernet(0x8847, &stack);
        let peeled = crate::dissect::peel_ethernet(&frame).unwrap();
        assert_eq!(source(&peeled.packet), INNER_ADDRESS);
        assert!(peeled.link.is_some());
    }

    #[test]
    fn an_mpls_control_word_is_skipped_before_ethernet() {
        let pseudowire = mpls(&[&[0; 4][..], &inner_frame()].concat());
        let frame = ethernet(0x8847, &pseudowire);
        let peeled = crate::dissect::peel_ethernet(&frame).unwrap();
        assert_eq!(source(&peeled.packet), INNER_ADDRESS);
        assert!(peeled.link.is_none());
    }

    #[test]
    fn a_fragment_is_not_peeled() {
        let packet = fragment(&over_gre(&gre(0x0800, &inner())), 0);
        assert_eq!(peeled_source(&packet), OUTER_ADDRESS);
    }
}
