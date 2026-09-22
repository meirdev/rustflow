//! Packet slicing with support for MPLS, VXLAN, Geneve, GRE, and ERSPAN
//! encapsulation, plus UDP payload extraction from captured packets.
//!
//! Slicing is lax: a sampled header is a clip of the first bytes of a
//! packet, so the IP length field claims more bytes than are present. The
//! headers that fit are decoded and the rest is ignored. Callers that need
//! a whole packet, like [`parse_udp_packet`], check for truncation
//! themselves.

use std::net::IpAddr;

use etherparse::{EtherType, IpNumber, LaxNetSlice, LaxSlicedPacket, TransportSlice};

/// The deepest packet successfully parsed within the tunnel depth limit.
pub struct Peeled<'a> {
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
pub fn peel_ethernet(frame: &[u8]) -> Option<Peeled<'_>> {
    LaxSlicedPacket::from_ethernet(frame).ok().map(peel)
}

/// Like [`peel_ethernet`], but starts at an IPv4 or IPv6 header.
pub fn peel_ip(packet: &[u8]) -> Option<Peeled<'_>> {
    LaxSlicedPacket::from_ip(packet).ok().map(peel)
}

/// Peels an already sliced packet.
pub fn peel(sliced: LaxSlicedPacket<'_>) -> Peeled<'_> {
    peel_with(sliced, false)
}

/// Like [`peel`], but only descends through an enclosing packet that is
/// whole: a truncated outer IP packet or a UDP header whose length does
/// not match its bytes stops the peeling there, so the caller's checks
/// see the bad layer rather than something inside it.
fn peel_strict(sliced: LaxSlicedPacket<'_>) -> Peeled<'_> {
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

/// Whether the IP packet is all there: not truncated, not a fragment, and
/// with a UDP length that matches the bytes when the transport is UDP. A
/// packet with no IP layer yet, such as a frame carrying an MPLS stack,
/// has nothing to check.
fn is_complete(sliced: &LaxSlicedPacket<'_>) -> bool {
    let Some(ip_payload) = sliced.ip_payload() else {
        return true;
    };
    if ip_payload.incomplete || ip_payload.fragmented {
        return false;
    }
    match &sliced.transport {
        Some(TransportSlice::Udp(udp)) => udp.payload().len() + 8 == usize::from(udp.length()),
        _ => true,
    }
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

fn encapsulated<'a>(sliced: &LaxSlicedPacket<'a>) -> Option<Inner<'a>> {
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

/// Extracts the source IP address and a copy of the UDP payload after
/// peeling supported tunnels, for replaying captured exporter traffic.
///
/// `link_type` is the capture's pcap link-layer header type number
/// (Ethernet, Linux cooked v1 and v2, and raw IP are read; frames of any
/// other type are `None`). Only a whole datagram is returned: a truncated
/// or fragmented one is `None`.
pub fn parse_udp_packet(link_type: u32, frame: &[u8]) -> Option<(IpAddr, Vec<u8>)> {
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
    Some((source_ip, udp.payload().to_vec()))
}
