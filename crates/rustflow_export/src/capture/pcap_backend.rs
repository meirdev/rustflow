//! libpcap/Npcap capture backend: works on Linux, macOS/BSD (BPF), and
//! Windows (requires the Npcap driver).

use anyhow::{Context, Result, bail};
use log::{debug, info};
use pcap::{Active, Capture, Linktype};

use super::{
    CaptureBackend, CaptureConfig, CaptureStats, PacketInfo, Sampler, parse_ethernet, parse_ip,
};

/// Snap length: enough for link, network, and transport headers.
const SNAPLEN: i32 = 2048;

/// How the link layer of this device is framed.
enum LinkLayer {
    /// Ethernet II frames.
    Ethernet,
    /// BSD loopback: a 4-byte address-family word, then the IP header.
    Loopback,
    /// Raw IP, no link header.
    RawIp,
}

pub struct PcapCapture {
    capture: Capture<Active>,
    link_layer: LinkLayer,
    sampler: Sampler,
    section_length: Option<usize>,
}

impl PcapCapture {
    pub fn new(interface: &str, config: &CaptureConfig) -> Result<Self> {
        let promiscuous = config.promiscuous;
        info!("Opening pcap capture on interface: {}", interface);

        let capture = Capture::from_device(interface)
            .with_context(|| format!("failed to open device '{interface}'"))?
            .promisc(promiscuous)
            .snaplen(SNAPLEN)
            .timeout(1000) // ms; keeps the caller's loop servicing timers
            .immediate_mode(true)
            .open()
            .with_context(|| format!("failed to start capture on '{interface}'"))?;

        let datalink = capture.get_datalink();
        let link_layer = match datalink {
            Linktype::ETHERNET => LinkLayer::Ethernet,
            Linktype::NULL | Linktype::LOOP => LinkLayer::Loopback,
            Linktype::RAW => LinkLayer::RawIp,
            other => bail!(
                "unsupported datalink type {:?} on '{}'; only Ethernet, loopback, and raw IP are supported",
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
            sampler: Sampler::new(config.sampling),
            section_length: config.section_length,
        })
    }
}

impl CaptureBackend for PcapCapture {
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

        let parsed = match self.link_layer {
            LinkLayer::Ethernet => parse_ethernet(packet.data),
            // The 4-byte family word's byte order varies by platform;
            // etherparse detects the IP version itself, so just skip it.
            LinkLayer::Loopback => parse_ip(packet.data.get(4..)?),
            LinkLayer::RawIp => parse_ip(packet.data),
        };

        parsed.map(|mut info| {
            info.frame_length = packet.header.len;
            info.observation_time_ms =
                packet.header.ts.tv_sec as i64 * 1_000 + packet.header.ts.tv_usec as i64 / 1_000;
            info.section = self
                .section_length
                .map(|n| packet.data[..n.min(packet.data.len())].to_vec());
            info
        })
    }

    fn stats(&self) -> CaptureStats {
        self.sampler.stats()
    }
}
