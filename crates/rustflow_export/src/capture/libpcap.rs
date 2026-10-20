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
    pub fn new(interface: &str, promiscuous: bool, filter: Option<&str>) -> Result<Self> {
        info!("Opening pcap capture on interface: {}", interface);

        let mut capture = pcap::Capture::from_device(interface)
            .with_context(|| format!("Failed to open device '{interface}'"))?
            .promisc(promiscuous)
            .snaplen(SNAPLEN)
            // Bounds the caller's wait so its timers keep running.
            .timeout(1000)
            .immediate_mode(true)
            .open()
            .with_context(|| format!("Failed to start capture on '{interface}'"))?;

        if let Some(expression) = filter {
            capture
                .filter(expression, true)
                .with_context(|| format!("Invalid filter '{expression}'"))?;
        }

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

/// Classic BPF `ret` with a constant; libpcap's accepting returns.
#[cfg(target_os = "linux")]
const BPF_RET_K: u16 = 0x06;

/// Compiles a tcpdump expression for Ethernet frames into a program an
/// `AF_PACKET` socket runs in the kernel. Accepting returns are set to
/// `snaplen`, as the socket's own snap length program would.
#[cfg(target_os = "linux")]
pub fn compile(expression: &str, snaplen: u32) -> Result<Vec<libc::sock_filter>> {
    let program = pcap::Capture::dead(Linktype::ETHERNET)?
        .compile(expression, true)
        .with_context(|| format!("Invalid filter '{expression}'"))?;
    let instructions = program.get_instructions();
    // `BpfInstruction` is a transparent wrapper of libpcap's `bpf_insn`,
    // which has the layout of `sock_filter`.
    let instructions: &[libc::sock_filter] =
        unsafe { std::slice::from_raw_parts(instructions.as_ptr().cast(), instructions.len()) };
    Ok(instructions
        .iter()
        .map(|instruction| {
            let mut instruction = *instruction;
            if instruction.code == BPF_RET_K && instruction.k != 0 {
                instruction.k = snaplen;
            }
            instruction
        })
        .collect())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn compiled_filters_accept_with_the_snap_length() {
        let program = compile("udp port 53", 2048).unwrap();
        let returns: Vec<u32> = program
            .iter()
            .filter(|instruction| instruction.code == BPF_RET_K)
            .map(|instruction| instruction.k)
            .collect();
        assert!(returns.contains(&2048), "{returns:?}");
        assert!(returns.contains(&0), "{returns:?}");
        assert!(returns.iter().all(|&k| k == 0 || k == 2048), "{returns:?}");
        assert!(program.len() > returns.len());

        assert!(compile("udp port", 2048).is_err());
    }
}
