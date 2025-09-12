use std::net::IpAddr;

use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::udp::UdpPacket;

pub fn parse_udp_packet(packet: &[u8]) -> Result<(IpAddr, Vec<u8>), ()> {
    let eth_packet = EthernetPacket::new(&packet).ok_or(())?;

    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
        return Err(());
    }

    let ip_packet = Ipv4Packet::new(eth_packet.payload()).ok_or(())?;

    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return Err(());
    }

    let source_ip = ip_packet.get_source();

    let udp_packet = UdpPacket::new(ip_packet.payload()).ok_or(())?;

    let payload = udp_packet.payload().to_owned();

    return Ok((IpAddr::V4(source_ip), payload));
}
