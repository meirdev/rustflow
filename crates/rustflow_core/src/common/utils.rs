use std::net::IpAddr;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

pub fn parse_udp_packet(packet: &[u8]) -> Option<(IpAddr, Vec<u8>)> {
    let sliced = SlicedPacket::from_ethernet(packet)
        .ok()
        .filter(|s| s.net.is_some())
        .or_else(|| {
            SlicedPacket::from_linux_sll(packet)
                .ok()
                .filter(|s| s.net.is_some())
        })
        // Linux cooked capture v2 (SLL2)
        .or_else(|| packet.get(20..).and_then(|p| SlicedPacket::from_ip(p).ok()))
        .or_else(|| SlicedPacket::from_ip(packet).ok())?;

    let source_ip = match sliced.net {
        Some(InternetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().source_addr()),
        Some(InternetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().source_addr()),
        _ => return None,
    };

    let payload = match sliced.transport {
        Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
        _ => return None,
    };

    Some((source_ip, payload))
}
