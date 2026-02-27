use anyhow::{anyhow, Result};
use etherparse::{SlicedPacket, TransportSlice};
use log::{debug, error, info};
use pcap::{Capture, Device};
use std::net::Ipv4Addr;

use crate::flow::FlowKey;

pub struct PacketCapture {
    capture: Capture<pcap::Active>,
}

impl PacketCapture {
    pub fn new(interface: &str, promiscuous: bool) -> Result<Self> {
        info!("Opening capture on interface: {}", interface);

        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| anyhow!("Interface '{}' not found", interface))?;

        let capture = Capture::from_device(device)?
            .promisc(promiscuous)
            .timeout(1000)
            .open()?;

        Ok(Self { capture })
    }

    pub fn next_packet(&mut self) -> Option<PacketInfo> {
        match self.capture.next_packet() {
            Ok(packet) => {
                match parse_packet(packet.data) {
                    Some(info) => {
                        debug!(
                            "Captured packet: {}:{} -> {}:{} proto={} size={}",
                            info.flow_key.source_ip,
                            info.flow_key.source_port,
                            info.flow_key.destination_ip,
                            info.flow_key.destination_port,
                            info.flow_key.protocol,
                            info.packet_size
                        );
                        Some(info)
                    }
                    None => None,
                }
            }
            Err(pcap::Error::TimeoutExpired) => None,
            Err(e) => {
                error!("Error capturing packet: {}", e);
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub flow_key: FlowKey,
    pub packet_size: u64,
    pub tcp_flags: u16,
}

fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    // Use etherparse to parse the packet
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            return None;
        }
    };

    // Extract IPv4 information
    let (source_ip, dest_ip, protocol, total_length) = match sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                Ipv4Addr::from(header.source()),
                Ipv4Addr::from(header.destination()),
                header.protocol().0,
                header.total_len() as u64,
            )
        }
        Some(etherparse::NetSlice::Ipv6(_)) => {
            // Skip IPv6 packets for now
            debug!("Skipping IPv6 packet");
            return None;
        }
        None => {
            debug!("No IP layer found");
            return None;
        }
    };

    // Extract transport layer information
    let (source_port, dest_port, tcp_flags) = match sliced.transport {
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
        _ => {
            (0, 0, 0)
        }
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
