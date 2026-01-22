use std::net::IpAddr;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

pub fn parse_udp_packet(packet: &[u8]) -> Result<(IpAddr, Vec<u8>), ()> {
    let sliced = SlicedPacket::from_ethernet(packet).map_err(|_| ())?;

    let source_ip = match sliced.net {
        Some(InternetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().source_addr()),
        Some(InternetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().source_addr()),
        Some(InternetSlice::Arp(_)) | None => return Err(()),
    };

    let payload = match sliced.transport {
        Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
        _ => return Err(()),
    };

    Ok((source_ip, payload))
}
