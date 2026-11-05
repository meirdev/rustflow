//! Packets for tests: the outer one from [`OUTER`], what a tunnel carries
//! from [`INNER`], so a test can tell how deep peeling went.

use std::net::Ipv4Addr;

use etherparse::{IpFragOffset, IpNumber, Ipv4Header, LaxNetSlice, LaxSlicedPacket, PacketBuilder};

pub(crate) const OUTER: [u8; 4] = [10, 0, 0, 1];
pub(crate) const INNER: [u8; 4] = [192, 0, 2, 1];
const DESTINATION: [u8; 4] = [198, 51, 100, 1];
const MACS: [u8; 12] = [2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1];

pub(crate) fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    [&MACS[..], &ether_type.to_be_bytes(), payload].concat()
}

/// An IPv4 packet carrying `payload` as protocol `protocol`.
pub(crate) fn ipv4(source: [u8; 4], protocol: IpNumber, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(source, DESTINATION, 64)
        .write(&mut packet, protocol, payload)
        .unwrap();
    packet
}

pub(crate) fn ipv4_udp(source: [u8; 4], destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(source, DESTINATION, 64)
        .udp(1000, destination_port)
        .write(&mut packet, payload)
        .unwrap();
    packet
}

/// A GRE header with no optional fields, then `payload`.
pub(crate) fn gre(protocol: u16, payload: &[u8]) -> Vec<u8> {
    [&[0, 0][..], &protocol.to_be_bytes(), payload].concat()
}

/// One MPLS label, the bottom of its stack, then `payload`.
pub(crate) fn mpls(payload: &[u8]) -> Vec<u8> {
    [&[0x00, 0x01, 0x01, 0x40][..], payload].concat()
}

/// `packet`, an IPv4 packet, made a fragment at `offset` eight-byte units
/// with more to follow.
pub(crate) fn fragment(packet: &[u8], offset: u16) -> Vec<u8> {
    let (mut header, rest) = Ipv4Header::from_slice(packet).unwrap();
    header.more_fragments = true;
    header.fragment_offset = IpFragOffset::try_new(offset).unwrap();
    header.header_checksum = header.calc_header_checksum();
    let mut fragment = header.to_bytes().to_vec();
    fragment.extend_from_slice(rest);
    fragment
}

/// `packet`, an IPv4 packet, with a total length of 0: shorter than its
/// header.
pub(crate) fn zero_total_length(packet: &[u8]) -> Vec<u8> {
    let (mut header, rest) = Ipv4Header::from_slice(packet).unwrap();
    header.total_len = 0;
    header.header_checksum = header.calc_header_checksum();
    let mut packet = header.to_bytes().to_vec();
    packet.extend_from_slice(rest);
    packet
}

pub(crate) fn source(packet: &LaxSlicedPacket<'_>) -> Option<Ipv4Addr> {
    match &packet.net {
        Some(LaxNetSlice::Ipv4(ipv4)) => Some(ipv4.header().source_addr()),
        _ => None,
    }
}
