use std::net::IpAddr;

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice};

use crate::peel::{Peeled, is_complete, peel_strict};

/// The link layer a capture file declares for its frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkType {
    Ethernet,
    /// Linux cooked capture, `tcpdump -i any` on older kernels.
    LinuxSll,
    /// Linux cooked capture v2.
    LinuxSll2,
    /// Frames start at the IP header.
    RawIp,
}

impl LinkType {
    /// From a pcap link-layer header type number.
    fn from_pcap(link_type: u32) -> Option<Self> {
        match link_type {
            1 => Some(Self::Ethernet),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            12 | 14 | 101 | 228 | 229 => Some(Self::RawIp),
            _ => None,
        }
    }
}

const LINUX_SLL_HEADER_LEN: usize = 16;
const LINUX_SLL2_HEADER_LEN: usize = 20;

/// The UDP payload of a captured frame, and the IP address that sent it,
/// after peeling supported tunnels: what a collector reads from captured
/// exporter traffic.
///
/// `link_type` is the capture's pcap link-layer header type number
/// (Ethernet, Linux cooked v1 and v2, and raw IP are read; frames of any
/// other type are `None`). Only a whole datagram is returned: a truncated
/// or fragmented one is `None`.
pub fn udp_payload(link_type: u32, frame: &[u8]) -> Option<(IpAddr, &[u8])> {
    let sliced = match LinkType::from_pcap(link_type)? {
        LinkType::Ethernet => LaxSlicedPacket::from_ethernet(frame).ok()?,
        // Both cooked headers carry the protocol as an ethertype: v1 in
        // its last two bytes, v2 in its first two.
        LinkType::LinuxSll => {
            let (header, payload) = frame.split_at_checked(LINUX_SLL_HEADER_LEN)?;
            let ether_type = EtherType(u16::from_be_bytes([header[14], header[15]]));
            LaxSlicedPacket::from_ether_type(ether_type, payload)
        }
        LinkType::LinuxSll2 => {
            let (header, payload) = frame.split_at_checked(LINUX_SLL2_HEADER_LEN)?;
            let ether_type = EtherType(u16::from_be_bytes([header[0], header[1]]));
            LaxSlicedPacket::from_ether_type(ether_type, payload)
        }
        LinkType::RawIp => LaxSlicedPacket::from_ip(frame).ok()?,
    };
    let Peeled { packet, .. } = peel_strict(sliced);
    if !is_complete(&packet) {
        return None;
    }
    let source_ip = match &packet.net {
        Some(LaxNetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().source_addr()),
        Some(LaxNetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().source_addr()),
        _ => return None,
    };
    let Some(TransportSlice::Udp(udp)) = &packet.transport else {
        return None;
    };
    Some((source_ip, udp.payload()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use etherparse::{IpNumber, PacketBuilder};

    use super::*;
    use crate::test_packets::*;

    const PAYLOAD: &[u8] = b"flow";
    const ETHERNET: u32 = 1;
    const LINUX_SLL: u32 = 113;
    const LINUX_SLL2: u32 = 276;
    const RAW_IP: u32 = 101;

    fn datagram() -> Vec<u8> {
        ipv4_udp(INNER, 2055, PAYLOAD)
    }

    fn sent_from_inner() -> Option<(IpAddr, &'static [u8])> {
        Some((IpAddr::V4(Ipv4Addr::from(INNER)), PAYLOAD))
    }

    #[test]
    fn each_supported_link_type_gives_the_source_and_payload() {
        let sll = [&[0; 14][..], &[0x08, 0x00], &datagram()].concat();
        let sll2 = [&[0x08, 0x00][..], &[0; 18], &datagram()].concat();
        for (link_type, frame) in [
            (ETHERNET, ethernet(0x0800, &datagram())),
            (LINUX_SLL, sll),
            (LINUX_SLL2, sll2),
            (RAW_IP, datagram()),
        ] {
            assert_eq!(
                udp_payload(link_type, &frame),
                sent_from_inner(),
                "link type {link_type}"
            );
        }
    }

    #[test]
    fn ipv6_datagrams_give_their_source() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut packet = Vec::new();
        PacketBuilder::ipv6(source.octets(), [0; 16], 64)
            .udp(1000, 2055)
            .write(&mut packet, PAYLOAD)
            .unwrap();
        assert_eq!(
            udp_payload(RAW_IP, &packet),
            Some((IpAddr::V6(source), PAYLOAD))
        );
    }

    #[test]
    fn a_tunnelled_datagram_is_peeled() {
        let vxlan = [
            &[0x08, 0, 0, 0, 0, 0, 1, 0][..],
            &ethernet(0x0800, &datagram()),
        ]
        .concat();
        let frame = ethernet(0x0800, &ipv4_udp(OUTER, 4789, &vxlan));
        assert_eq!(udp_payload(ETHERNET, &frame), sent_from_inner());
    }

    #[test]
    fn only_a_whole_udp_datagram_is_returned() {
        let mut truncated = datagram();
        truncated.pop();
        let mut udp_length_too_long = datagram();
        udp_length_too_long[25] += 1;
        let not_udp = ipv4(INNER, IpNumber::GRE, PAYLOAD);
        for packet in [
            truncated,
            udp_length_too_long,
            fragment(&datagram(), 0),
            not_udp,
        ] {
            assert_eq!(udp_payload(RAW_IP, &packet), None);
        }
    }

    #[test]
    fn other_link_types_are_not_read() {
        assert_eq!(udp_payload(0, &datagram()), None);
    }
}
