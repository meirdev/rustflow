//! Dissects captured packets: through link layers (Ethernet, VLAN tags,
//! Linux cooked captures), MPLS and tunnels (GRE, ERSPAN, VXLAN, Geneve) to
//! their IP and transport headers, given back as plain values.
//!
//! Slicing is lax: a sampled header is a clip of the first bytes of a
//! packet, so the IP length field claims more bytes than are present. The
//! headers that fit are decoded and the rest is ignored. Callers that need
//! a whole packet, like [`udp_payload`], check for truncation
//! themselves.

pub use headers::{Headers, Ipv4, Ipv6, Link, Net, Transport};
pub use udp::udp_payload;

use crate::dissect::peel::{peel_ethernet, peel_ip};

mod headers;
mod peel;
#[cfg(test)]
mod test_packets;
mod tunnel;
mod udp;

/// The headers of a frame that starts at its Ethernet header, peeled
/// through any tunnels; `None` if the Ethernet header does not fit.
pub fn ethernet(frame: &[u8]) -> Option<Headers> {
    peel_ethernet(frame).map(|peeled| Headers::of(&peeled))
}

/// The headers of a packet that starts at its IPv4 or IPv6 header, peeled
/// through any tunnels; `None` if the IP header does not parse.
pub fn ip(packet: &[u8]) -> Option<Headers> {
    peel_ip(packet).map(|peeled| Headers::of(&peeled))
}
