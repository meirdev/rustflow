//! Packet slicing with support for MPLS, VXLAN, Geneve, GRE, and ERSPAN
//! encapsulation, plus UDP payload extraction from captured packets.

use std::net::IpAddr;

use etherparse::{EtherType, InternetSlice, IpNumber, SlicedPacket, TransportSlice};

/// The deepest packet successfully parsed within the tunnel depth limit.
pub struct Peeled<'a> {
    /// The enclosing packet retained for its link-layer metadata when
    /// `packet` has no link header. `None` if `packet` has its own link
    /// header or no enclosing link layer was available.
    pub link: Option<SlicedPacket<'a>>,
    /// The last successfully parsed packet, which may still be encapsulated.
    pub packet: SlicedPacket<'a>,
}

/// Maximum number of decapsulation steps; an MPLS label stack is one step.
const MAX_TUNNEL_DEPTH: u8 = 4;

/// Peels a frame that starts at its Ethernet header.
///
/// Inner Ethernet frames replace the enclosing link-layer metadata. Inner
/// IP packets retain it in [`Peeled::link`]. Peeling stops at an unsupported
/// or malformed encapsulation, or when the tunnel depth limit is reached.
/// Returns `None` if the initial Ethernet frame cannot be parsed.
pub fn peel_ethernet(frame: &[u8]) -> Option<Peeled<'_>> {
    SlicedPacket::from_ethernet(frame).ok().map(peel)
}

/// Like [`peel_ethernet`], but starts at an IPv4 or IPv6 header.
pub fn peel_ip(packet: &[u8]) -> Option<Peeled<'_>> {
    SlicedPacket::from_ip(packet).ok().map(peel)
}

/// Peels an already sliced packet.
pub fn peel(sliced: SlicedPacket<'_>) -> Peeled<'_> {
    let mut link = None;
    let mut packet = sliced;
    for _ in 0..MAX_TUNNEL_DEPTH {
        match encapsulated(&packet) {
            Some(Inner::Ethernet(frame)) => match SlicedPacket::from_ethernet(frame) {
                Ok(inner) => {
                    link = None;
                    packet = inner;
                }
                Err(_) => break,
            },
            Some(Inner::Ip(bytes)) => match SlicedPacket::from_ip(bytes) {
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

/// What a recognised encapsulation carries.
enum Inner<'a> {
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

fn encapsulated<'a>(sliced: &SlicedPacket<'a>) -> Option<Inner<'a>> {
    // Check after any link-layer extensions, such as VLAN tags, because
    // etherparse leaves the MPLS label stack in the Ethernet payload.
    let ether_payload = match sliced.link_exts.last() {
        Some(ext) => ext.ether_payload(),
        None => sliced.link.as_ref().and_then(|link| link.ether_payload()),
    };
    if let Some(payload) = ether_payload
        && matches!(payload.ether_type, MPLS_UNICAST | MPLS_MULTICAST)
    {
        return mpls_inner(payload.payload);
    }

    let ip_payload = match &sliced.net {
        Some(InternetSlice::Ipv4(ipv4)) => ipv4.payload(),
        Some(InternetSlice::Ipv6(ipv6)) => ipv6.payload(),
        _ => return None,
    };
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
/// This is a heuristic: Ethernet destination addresses can have the same
/// leading nibbles, so some frames are ambiguous without pseudowire metadata.
fn mpls_inner(mut bytes: &[u8]) -> Option<Inner<'_>> {
    loop {
        let (label, rest) = bytes.split_first_chunk::<4>()?;
        bytes = rest;
        if label[2] & 0x01 != 0 {
            break;
        }
    }
    match bytes.first()? >> 4 {
        4 | 6 => Some(Inner::Ip(bytes)),
        0 => Some(Inner::Ethernet(bytes.get(4..)?)),
        _ => Some(Inner::Ethernet(bytes)),
    }
}

/// RFC 2784 and 2890 GRE, plus the ERSPAN headers Cisco puts behind it.
fn gre_inner(bytes: &[u8]) -> Option<Inner<'_>> {
    let (fixed, _) = bytes.split_first_chunk::<4>()?;
    let flags = u16::from_be_bytes([fixed[0], fixed[1]]);
    let protocol = EtherType(u16::from_be_bytes([fixed[2], fixed[3]]));
    if flags & 0x0007 != 0 {
        // Only GRE version 0 is supported.
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

/// Extracts the source IP address and a copy of the UDP payload after
/// peeling supported tunnels, for replaying captured exporter traffic.
///
/// Guesses the capture format by trying Ethernet, Linux cooked capture v1,
/// a 20-byte Linux cooked capture v2 header followed by IP, and raw IP, in
/// that order. The first candidate with a network layer after peeling is
/// selected; returns `None` if that packet is not IP/UDP or no candidate fits.
pub fn parse_udp_packet(packet: &[u8]) -> Option<(IpAddr, Vec<u8>)> {
    // Check for a network layer after peeling so MPLS frames can qualify.
    fn with_net(sliced: Result<SlicedPacket<'_>, impl std::error::Error>) -> Option<Peeled<'_>> {
        let peeled = peel(sliced.ok()?);
        peeled.packet.net.is_some().then_some(peeled)
    }
    let Peeled { packet, .. } = with_net(SlicedPacket::from_ethernet(packet))
        .or_else(|| with_net(SlicedPacket::from_linux_sll(packet)))
        // SLL2 fallback: skip its fixed header without validating its fields.
        .or_else(|| {
            packet
                .get(20..)
                .and_then(|p| with_net(SlicedPacket::from_ip(p)))
        })
        .or_else(|| with_net(SlicedPacket::from_ip(packet)))?;

    let source_ip = match packet.net {
        Some(InternetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().source_addr()),
        Some(InternetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().source_addr()),
        _ => return None,
    };

    let payload = match packet.transport {
        Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
        _ => return None,
    };

    Some((source_ip, payload))
}
