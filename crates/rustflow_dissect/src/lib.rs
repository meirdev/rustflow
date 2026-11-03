//! Dissects captured packets: through link layers (Ethernet, VLAN tags,
//! Linux cooked captures), MPLS and tunnels (GRE, ERSPAN, VXLAN, Geneve) to
//! their IP and transport headers, on top of `etherparse`.
//!
//! Slicing is lax: a sampled header is a clip of the first bytes of a
//! packet, so the IP length field claims more bytes than are present. The
//! headers that fit are decoded and the rest is ignored. Callers that need
//! a whole packet, like [`udp_payload`], check for truncation
//! themselves.

pub use peel::{Peeled, first_fragment_transport, peel, peel_ethernet, peel_ip};
pub use udp::udp_payload;

mod peel;
#[cfg(test)]
mod test_packets;
mod tunnel;
mod udp;
