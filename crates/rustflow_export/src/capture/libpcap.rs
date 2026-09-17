use anyhow::{Context, Result, bail};
use log::{debug, info};
use pcap::{Active, Linktype};

use super::packet::{Sampler, parse_ethernet, parse_ip};
use super::{Capture, PacketInfo};

/// Enough for link, network and transport headers.
const SNAPLEN: i32 = 2048;

enum LinkLayer {
    Ethernet,
    /// BSD loopback: a 4-byte address-family word, then the IP header.
    Loopback,
    RawIp,
}

pub struct Libpcap {
    capture: pcap::Capture<Active>,
    link_layer: LinkLayer,
    sampler: Sampler,
}

impl Libpcap {
    pub fn new(interface: &str, promiscuous: bool, sampling_interval: u32) -> Result<Self> {
        info!("Opening pcap capture on interface: {}", interface);

        let capture = pcap::Capture::from_device(interface)
            .with_context(|| format!("Failed to open device '{interface}'"))?
            .promisc(promiscuous)
            .snaplen(SNAPLEN)
            // Bounds the caller's wait so its timers keep running.
            .timeout(1000)
            .immediate_mode(true)
            .open()
            .with_context(|| format!("Failed to start capture on '{interface}'"))?;

        let datalink = capture.get_datalink();
        let link_layer = match datalink {
            Linktype::ETHERNET => LinkLayer::Ethernet,
            Linktype::NULL | Linktype::LOOP => LinkLayer::Loopback,
            Linktype::RAW => LinkLayer::RawIp,
            other => bail!(
                "Unsupported link type {} on '{}'; only Ethernet, loopback and raw IP are supported",
                other.get_name().unwrap_or_else(|_| other.0.to_string()),
                interface
            ),
        };

        if promiscuous {
            info!("Promiscuous mode enabled on {}", interface);
        }

        Ok(Self {
            capture,
            link_layer,
            sampler: Sampler::new(sampling_interval),
        })
    }
}

impl Capture for Libpcap {
    fn next_packet(&mut self) -> Option<PacketInfo> {
        let packet = match self.capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired) => return None,
            Err(e) => {
                debug!("pcap read error: {}", e);
                return None;
            }
        };

        if !self.sampler.select() {
            return None;
        }

        match self.link_layer {
            LinkLayer::Ethernet => parse_ethernet(packet.data),
            // The family word's byte order varies by platform; etherparse
            // detects the IP version itself, so skip the word.
            LinkLayer::Loopback => parse_ip(packet.data.get(4..)?),
            LinkLayer::RawIp => parse_ip(packet.data),
        }
    }
}
