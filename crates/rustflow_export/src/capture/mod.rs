//! Packet capture backends.
//!
//! Each platform offers different capture mechanisms; the exporter picks one
//! through [`open_capture`]:
//!
//! - `af-packet` (Linux): hand-rolled `AF_PACKET` + `PACKET_MMAP` ring, no
//!   external dependencies.
//! - `pcap` (all platforms, `pcap` cargo feature): libpcap on Linux/macos/BSD,
//!   Npcap on Windows.

#[cfg(any(target_os = "linux", feature = "pcap"))]
use std::net::Ipv4Addr;

use anyhow::Result;
#[cfg(not(all(target_os = "linux", feature = "pcap")))]
use anyhow::bail;
#[cfg(any(target_os = "linux", feature = "pcap"))]
use etherparse::{LaxSlicedPacket, TransportSlice};
#[cfg(any(target_os = "linux", feature = "pcap"))]
use log::debug;

use crate::flow::FlowKey;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(feature = "pcap")]
mod pcap_backend;

/// A source of sampled, parsed packets.
///
/// `next_packet` blocks for at most about a second and returns `None` when no
/// selected packet arrived in that window (idle link, sampled-out packet, or
/// an unparseable frame), so the caller's loop keeps servicing timers.
pub trait CaptureBackend {
    fn next_packet(&mut self) -> Option<PacketInfo>;

    /// Totals since the capture was opened, for PSAMP Selection Sequence
    /// Statistics (RFC 5476 section 6.5.3).
    fn stats(&self) -> CaptureStats;
}

/// Packet counters at the sampler.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    /// Packets that reached the sampler.
    pub packets_observed: u64,
    /// Packets the sampler selected.
    pub packets_selected: u64,
}

/// Which capture backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CaptureBackendKind {
    /// Best available backend for this platform.
    Auto,
    /// AF_PACKET mmap ring (Linux only).
    AfPacket,
    /// libpcap / Npcap (requires the `pcap` cargo feature).
    Pcap,
}

/// Capture configuration shared by every backend.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub promiscuous: bool,
    pub sampling: SamplingConfig,
    /// When set, copy up to this many bytes from the start of each selected
    /// frame into [`PacketInfo::section`] (for PSAMP Packet Reports).
    pub section_length: Option<usize>,
}

/// A configured packet sampling algorithm (RFC 5475 sampling schemes; the
/// PSAMP selectorAlgorithm identifiers 1-4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SamplingConfig {
    /// Systematic count-based: select 1 out of every `interval` packets.
    CountBased { interval: u32 },
    /// Systematic time-based: select all packets for `interval_us`, then
    /// skip for `space_us`, repeating.
    TimeBased { interval_us: u32, space_us: u32 },
    /// Random n-out-of-N: select exactly `size` packets out of every
    /// consecutive `population`.
    NOutOfN { size: u32, population: u32 },
    /// Uniform probabilistic: select each packet independently with
    /// probability `probability`.
    Probabilistic { probability: f64 },
}

impl SamplingConfig {
    /// Effective 1-in-N packet rate, where that is well defined (time-based
    /// sampling has no packet-count rate).
    pub fn effective_rate(&self) -> Option<u32> {
        match *self {
            SamplingConfig::CountBased { interval } => Some(interval.max(1)),
            SamplingConfig::TimeBased { .. } => None,
            SamplingConfig::NOutOfN { size, population } => Some((population / size.max(1)).max(1)),
            SamplingConfig::Probabilistic { probability } => {
                Some(((1.0 / probability).round() as u32).max(1))
            }
        }
    }
}

/// Open the requested capture backend on `interface`.
pub fn open_capture(
    kind: CaptureBackendKind,
    interface: &str,
    config: &CaptureConfig,
) -> Result<Box<dyn CaptureBackend>> {
    match kind {
        CaptureBackendKind::Auto => {
            #[cfg(target_os = "linux")]
            {
                open_af_packet(interface, config)
            }
            #[cfg(not(target_os = "linux"))]
            {
                open_pcap(interface, config)
            }
        }
        CaptureBackendKind::AfPacket => open_af_packet(interface, config),
        CaptureBackendKind::Pcap => open_pcap(interface, config),
    }
}

#[cfg(target_os = "linux")]
fn open_af_packet(interface: &str, config: &CaptureConfig) -> Result<Box<dyn CaptureBackend>> {
    Ok(Box::new(af_packet::AfPacketCapture::new(
        interface, config,
    )?))
}

#[cfg(not(target_os = "linux"))]
fn open_af_packet(_interface: &str, _config: &CaptureConfig) -> Result<Box<dyn CaptureBackend>> {
    bail!("the af-packet capture backend requires Linux; use --capture pcap")
}

#[cfg(feature = "pcap")]
fn open_pcap(interface: &str, config: &CaptureConfig) -> Result<Box<dyn CaptureBackend>> {
    Ok(Box::new(pcap_backend::PcapCapture::new(interface, config)?))
}

#[cfg(not(feature = "pcap"))]
fn open_pcap(_interface: &str, _config: &CaptureConfig) -> Result<Box<dyn CaptureBackend>> {
    bail!("this build has no pcap support; rebuild with `--features rustflow_export/pcap`")
}

/// Packet sampler implementing the RFC 5475 sampling schemes configured by
/// [`SamplingConfig`].
#[cfg(any(target_os = "linux", feature = "pcap"))]
pub(crate) struct Sampler {
    mode: SamplerMode,
    stats: CaptureStats,
}

#[cfg(any(target_os = "linux", feature = "pcap"))]
enum SamplerMode {
    CountBased {
        interval: u32,
        countdown: u32,
    },
    TimeBased {
        interval_us: u64,
        cycle_us: u64,
        start: std::time::Instant,
    },
    NOutOfN {
        size: u32,
        population: u32,
        remaining_population: u32,
        remaining_size: u32,
        rng: SplitMix64,
    },
    Probabilistic {
        /// `probability` scaled to the full u64 range.
        threshold: u64,
        rng: SplitMix64,
    },
}

#[cfg(any(target_os = "linux", feature = "pcap"))]
impl Sampler {
    pub(crate) fn new(config: SamplingConfig) -> Self {
        let mode = match config {
            SamplingConfig::CountBased { interval } => SamplerMode::CountBased {
                interval: interval.max(1),
                countdown: 1,
            },
            SamplingConfig::TimeBased {
                interval_us,
                space_us,
            } => SamplerMode::TimeBased {
                interval_us: u64::from(interval_us.max(1)),
                cycle_us: u64::from(interval_us.max(1)) + u64::from(space_us),
                start: std::time::Instant::now(),
            },
            SamplingConfig::NOutOfN { size, population } => {
                let population = population.max(1);
                SamplerMode::NOutOfN {
                    size: size.clamp(1, population),
                    population,
                    remaining_population: 0,
                    remaining_size: 0,
                    rng: SplitMix64::seeded(),
                }
            }
            SamplingConfig::Probabilistic { probability } => SamplerMode::Probabilistic {
                threshold: (probability.clamp(0.0, 1.0) * u64::MAX as f64) as u64,
                rng: SplitMix64::seeded(),
            },
        };

        Self {
            mode,
            stats: CaptureStats::default(),
        }
    }

    /// Count one observed packet; returns whether it is selected.
    pub(crate) fn select(&mut self) -> bool {
        self.stats.packets_observed += 1;
        let selected = match &mut self.mode {
            SamplerMode::CountBased {
                interval,
                countdown,
            } => {
                if *countdown > 1 {
                    *countdown -= 1;
                    false
                } else {
                    *countdown = *interval;
                    true
                }
            }
            SamplerMode::TimeBased {
                interval_us,
                cycle_us,
                start,
            } => (start.elapsed().as_micros() as u64) % *cycle_us < *interval_us,
            SamplerMode::NOutOfN {
                size,
                population,
                remaining_population,
                remaining_size,
                rng,
            } => {
                if *remaining_population == 0 {
                    *remaining_population = *population;
                    *remaining_size = *size;
                }
                // Knuth's Algorithm S: with `remaining_size` still to pick
                // out of `remaining_population` packets, select this packet
                // with probability remaining_size / remaining_population.
                let take =
                    rng.next() % u64::from(*remaining_population) < u64::from(*remaining_size);
                *remaining_population -= 1;
                if take {
                    *remaining_size -= 1;
                }
                take
            }
            SamplerMode::Probabilistic { threshold, rng } => rng.next() < *threshold,
        };

        if selected {
            self.stats.packets_selected += 1;
        }
        selected
    }

    pub(crate) fn stats(&self) -> CaptureStats {
        self.stats
    }
}

/// Small, fast PRNG (SplitMix64) for sampling decisions; not cryptographic.
#[cfg(any(target_os = "linux", feature = "pcap"))]
struct SplitMix64(u64);

#[cfg(any(target_os = "linux", feature = "pcap"))]
impl SplitMix64 {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub flow_key: FlowKey,
    pub packet_size: u64,
    pub tcp_flags: u16,
    /// Original frame length on the wire, in octets.
    pub frame_length: u32,
    /// Capture timestamp, milliseconds since the Unix epoch.
    pub observation_time_ms: i64,
    /// Leading bytes of the frame, when the capture was opened with
    /// [`CaptureConfig::section_length`].
    pub section: Option<Vec<u8>>,
}

/// Parse a packet starting at the Ethernet header. Lax slicing tolerates
/// frames truncated by the snap length.
#[cfg(any(target_os = "linux", feature = "pcap"))]
pub(crate) fn parse_ethernet(data: &[u8]) -> Option<PacketInfo> {
    match LaxSlicedPacket::from_ethernet(data) {
        Ok(sliced) => packet_info(&sliced),
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            None
        }
    }
}

/// Parse a packet starting at the IP header (loopback/raw-IP link types).
#[cfg(feature = "pcap")]
pub(crate) fn parse_ip(data: &[u8]) -> Option<PacketInfo> {
    match LaxSlicedPacket::from_ip(data) {
        Ok(sliced) => packet_info(&sliced),
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            None
        }
    }
}

#[cfg(any(target_os = "linux", feature = "pcap"))]
fn packet_info(sliced: &LaxSlicedPacket) -> Option<PacketInfo> {
    let (source_ip, dest_ip, protocol, total_length) = match &sliced.net {
        Some(etherparse::LaxNetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                Ipv4Addr::from(header.source()),
                Ipv4Addr::from(header.destination()),
                header.protocol().0,
                header.total_len() as u64,
            )
        }
        Some(etherparse::LaxNetSlice::Ipv6(_)) => {
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
        // Filled in by the capture backend.
        frame_length: 0,
        observation_time_ms: 0,
        section: None,
    })
}

#[cfg(all(test, any(target_os = "linux", feature = "pcap")))]
mod tests {
    use super::*;

    #[test]
    fn count_based_selects_exactly_one_in_n() {
        let mut sampler = Sampler::new(SamplingConfig::CountBased { interval: 10 });
        let selected = (0..1_000).filter(|_| sampler.select()).count();
        assert_eq!(selected, 100);
        assert_eq!(sampler.stats().packets_observed, 1_000);
        assert_eq!(sampler.stats().packets_selected, 100);
    }

    #[test]
    fn n_out_of_n_selects_exactly_n_per_population() {
        let mut sampler = Sampler::new(SamplingConfig::NOutOfN {
            size: 5,
            population: 100,
        });
        // Algorithm S selects exactly `size` in every complete population.
        let selected = (0..100_000).filter(|_| sampler.select()).count();
        assert_eq!(selected, 5_000);
    }

    #[test]
    fn probabilistic_selects_close_to_probability() {
        let mut sampler = Sampler::new(SamplingConfig::Probabilistic { probability: 0.25 });
        let selected = (0..100_000).filter(|_| sampler.select()).count();
        // Binomial std dev is ~137; 1500 is nearly 11 sigma.
        assert!((23_500..=26_500).contains(&selected), "selected {selected}");
    }

    #[test]
    fn time_based_selects_at_cycle_start() {
        let mut sampler = Sampler::new(SamplingConfig::TimeBased {
            interval_us: 1_000_000,
            space_us: 1_000_000,
        });
        // Immediately after creation we are inside the selection interval.
        assert!(sampler.select());
    }

    #[test]
    fn effective_rates() {
        assert_eq!(
            SamplingConfig::CountBased { interval: 100 }.effective_rate(),
            Some(100)
        );
        assert_eq!(
            SamplingConfig::NOutOfN {
                size: 5,
                population: 100
            }
            .effective_rate(),
            Some(20)
        );
        assert_eq!(
            SamplingConfig::Probabilistic { probability: 0.25 }.effective_rate(),
            Some(4)
        );
        assert_eq!(
            SamplingConfig::TimeBased {
                interval_us: 1,
                space_us: 9
            }
            .effective_rate(),
            None
        );
    }
}
