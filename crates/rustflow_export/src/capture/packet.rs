use std::net::Ipv4Addr;

use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};
use log::debug;

use super::PacketInfo;
use crate::flow::FlowKey;

/// Systematic count-based sampling: 1 out of every `interval` packets.
pub struct Sampler {
    interval: u32,
    countdown: u32,
}

impl Sampler {
    pub fn new(interval: u32) -> Self {
        Self {
            interval: interval.max(1),
            countdown: 1,
        }
    }

    pub fn select(&mut self) -> bool {
        if self.countdown > 1 {
            self.countdown -= 1;
            false
        } else {
            self.countdown = self.interval;
            true
        }
    }
}

/// Parse a frame starting at the Ethernet header. Lax slicing tolerates
/// frames truncated by the snap length.
pub fn parse_ethernet(data: &[u8]) -> Option<PacketInfo> {
    match LaxSlicedPacket::from_ethernet(data) {
        Ok(sliced) => packet_info(&sliced),
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            None
        }
    }
}

/// Parse a packet starting at the IP header (loopback and raw-IP links).
#[cfg(feature = "pcap")]
pub fn parse_ip(data: &[u8]) -> Option<PacketInfo> {
    match LaxSlicedPacket::from_ip(data) {
        Ok(sliced) => packet_info(&sliced),
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            None
        }
    }
}

fn packet_info(sliced: &LaxSlicedPacket) -> Option<PacketInfo> {
    let (source_ip, dest_ip, protocol, total_length) = match &sliced.net {
        Some(LaxNetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                Ipv4Addr::from(header.source()),
                Ipv4Addr::from(header.destination()),
                header.protocol().0,
                header.total_len() as u64,
            )
        }
        Some(LaxNetSlice::Ipv6(_)) => {
            debug!("Skipping IPv6 packet");
            return None;
        }
        None => {
            debug!("No IP layer found");
            return None;
        }
    };

    let (source_port, dest_port, tcp_flags) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let header = tcp.to_header();
            let flags = (header.ns as u16) << 8
                | (header.fin as u16)
                | ((header.syn as u16) << 1)
                | ((header.rst as u16) << 2)
                | ((header.psh as u16) << 3)
                | ((header.ack as u16) << 4)
                | ((header.urg as u16) << 5)
                | ((header.ece as u16) << 6)
                | ((header.cwr as u16) << 7);
            (header.source_port, header.destination_port, flags)
        }
        Some(TransportSlice::Udp(udp)) => {
            let header = udp.to_header();
            (header.source_port, header.destination_port, 0)
        }
        _ => (0, 0, 0),
    };

    Some(PacketInfo {
        flow_key: FlowKey {
            source_ip,
            destination_ip: dest_ip,
            protocol,
            source_port,
            destination_port: dest_port,
        },
        packet_size: total_length,
        tcp_flags,
    })
}
