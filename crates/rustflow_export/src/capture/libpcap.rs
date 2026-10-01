#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use anyhow::{Context, Result, bail};
use log::{debug, info};
use pcap::{Active, Linktype};

use super::{Capture, Frame, Link};

/// Enough for link, network and transport headers.
const SNAPLEN: i32 = 2048;

/// What a live capture reports for a raw-IP link on Linux and most BSDs;
/// `Linktype::RAW` is the value used in capture files.
const DLT_RAW: Linktype = Linktype(12);

enum LinkLayer {
    Ethernet,
    /// BSD loopback: a 4-byte address-family word, then the IP header.
    Loopback,
    RawIp,
}

pub struct Libpcap {
    capture: pcap::Capture<Active>,
    link_layer: LinkLayer,
}

impl Libpcap {
    pub fn new(interface: &str, promiscuous: bool) -> Result<Self> {
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

        // On Linux the read timeout only starts once a packet has arrived,
        // so an idle link would block forever; the wait is done with `poll`
        // on the descriptor instead.
        #[cfg(target_os = "linux")]
        let capture = capture
            .setnonblock()
            .with_context(|| format!("Failed to set '{interface}' non-blocking"))?;

        let datalink = capture.get_datalink();
        let link_layer = match datalink {
            Linktype::ETHERNET => LinkLayer::Ethernet,
            Linktype::NULL | Linktype::LOOP => LinkLayer::Loopback,
            DLT_RAW | Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => LinkLayer::RawIp,
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
        })
    }
}

impl Libpcap {
    /// Waits up to a second for the capture to become readable.
    #[cfg(target_os = "linux")]
    fn wait(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.capture.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, 1000) > 0 }
    }
}

impl Capture for Libpcap {
    fn link(&self) -> Link {
        match self.link_layer {
            LinkLayer::Ethernet => Link::Ethernet,
            LinkLayer::Loopback | LinkLayer::RawIp => Link::Ip,
        }
    }

    fn next_frame(&mut self) -> Option<Frame<'_>> {
        #[cfg(target_os = "linux")]
        if !self.wait() {
            return None;
        }

        let packet = match self.capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired) => return None,
            Err(e) => {
                debug!("pcap read error: {}", e);
                return None;
            }
        };

        // The family word's byte order varies by platform, and the IP
        // header after it states its own version, so the word is skipped.
        let skip = match self.link_layer {
            LinkLayer::Loopback => 4,
            LinkLayer::Ethernet | LinkLayer::RawIp => 0,
        };

        Some(Frame {
            data: packet.data.get(skip..)?,
            length: packet.header.len.saturating_sub(skip as u32),
        })
    }
}
