//! IPFIX exporter.
//!
//! Captures packets on a network interface, aggregates them into flows, and
//! exports them as IPFIX. Capture backends: `AF_PACKET` + `PACKET_RX_RING` on
//! Linux (no dependencies), libpcap/Npcap everywhere with the `pcap` feature.

mod capture;
mod exporter;
mod flow;
mod ipfix;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
pub use capture::CaptureBackendKind;
use chrono::{DateTime, Utc};
use clap::Args as ClapArgs;
use exporter::Exporter;
use flow::FlowCache;
use ipfix::data::PacketReport;
use log::{error, info, warn};

/// Which RFC 5475 sampling scheme selects packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SamplingAlgorithm {
    /// Systematic count-based: 1 out of every --sampling-packet-interval
    CountBased,
    /// Systematic time-based: --sampling-time-interval on,
    /// --sampling-time-space off (microseconds)
    TimeBased,
    /// Random --sampling-size out of every --sampling-population packets
    NOutOfN,
    /// Each packet selected with --sampling-probability
    Probabilistic,
}

/// What the exporter sends to the collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportMode {
    /// Aggregate packets into flows and export IPFIX Flow Records
    Flows,
    /// Export one PSAMP Packet Report per selected packet (RFC 5476)
    Packets,
}

/// Flush buffered packet reports once this many have accumulated, in
/// addition to the periodic once-a-second flush.
const PACKET_REPORT_FLUSH_COUNT: usize = 64;

#[cfg(target_os = "macos")]
const DEFAULT_INTERFACE: &str = "lo0";
#[cfg(not(target_os = "macos"))]
const DEFAULT_INTERFACE: &str = "lo";

/// Arguments for the `export` subcommand.
#[derive(ClapArgs, Debug, Clone)]
pub struct ExportArgs {
    /// Network interface to capture from
    #[arg(short, long, default_value = DEFAULT_INTERFACE)]
    pub interface: String,

    /// Capture backend (auto picks the best available for this platform)
    #[arg(long, value_enum, default_value_t = CaptureBackendKind::Auto)]
    pub capture: CaptureBackendKind,

    /// Collector host address
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub collector_host: String,

    /// Collector port
    #[arg(short = 'p', long, default_value = "4739")]
    pub collector_port: u16,

    /// Observation domain ID
    #[arg(long, default_value = "1")]
    pub observation_domain_id: u32,

    /// Active flow timeout in seconds
    #[arg(long, default_value = "60")]
    pub active_timeout: u64,

    /// Inactive flow timeout in seconds
    #[arg(long, default_value = "15")]
    pub inactive_timeout: u64,

    /// Template refresh rate in seconds
    #[arg(long, default_value = "300")]
    pub template_refresh_rate: u64,

    /// Packet sampling algorithm (RFC 5475)
    #[arg(long, value_enum, default_value_t = SamplingAlgorithm::CountBased)]
    pub sampling_algorithm: SamplingAlgorithm,

    /// Sampling packet interval: select 1 out of every N packets
    /// (count-based algorithm)
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub sampling_packet_interval: u32,

    /// Microseconds of each cycle spent selecting packets (time-based
    /// algorithm)
    #[arg(long, default_value = "100000", value_parser = clap::value_parser!(u32).range(1..))]
    pub sampling_time_interval: u32,

    /// Microseconds of each cycle spent skipping packets (time-based
    /// algorithm)
    #[arg(long, default_value = "900000")]
    pub sampling_time_space: u32,

    /// Packets to select out of each population (n-out-of-N algorithm)
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub sampling_size: u32,

    /// Population size to select from (n-out-of-N algorithm)
    #[arg(long, default_value = "100", value_parser = clap::value_parser!(u32).range(1..))]
    pub sampling_population: u32,

    /// Probability of selecting each packet, in (0, 1] (probabilistic
    /// algorithm)
    #[arg(long, default_value = "0.01")]
    pub sampling_probability: f64,

    /// Enable promiscuous mode
    #[arg(long)]
    pub promiscuous: bool,

    /// Export mode: aggregated flow records, or PSAMP per-packet reports
    #[arg(long, value_enum, default_value_t = ExportMode::Flows)]
    pub mode: ExportMode,

    /// Bytes of each captured frame to include in a PSAMP packet report
    #[arg(long, default_value = "128", value_parser = clap::value_parser!(u16).range(1..=2048))]
    pub section_length: u16,

    /// Seconds between PSAMP selection sequence statistics exports
    #[arg(long, default_value = "60", value_parser = clap::value_parser!(u64).range(1..))]
    pub stats_interval: u64,
}

impl ExportArgs {
    pub fn collector_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.collector_host, self.collector_port);
        addr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid collector address: {}", e))
    }

    /// The configured sampling scheme, validated.
    pub fn sampling_config(&self) -> Result<capture::SamplingConfig> {
        use capture::SamplingConfig;

        Ok(match self.sampling_algorithm {
            SamplingAlgorithm::CountBased => SamplingConfig::CountBased {
                interval: self.sampling_packet_interval,
            },
            SamplingAlgorithm::TimeBased => SamplingConfig::TimeBased {
                interval_us: self.sampling_time_interval,
                space_us: self.sampling_time_space,
            },
            SamplingAlgorithm::NOutOfN => {
                if self.sampling_size > self.sampling_population {
                    anyhow::bail!(
                        "--sampling-size ({}) cannot exceed --sampling-population ({})",
                        self.sampling_size,
                        self.sampling_population
                    );
                }
                SamplingConfig::NOutOfN {
                    size: self.sampling_size,
                    population: self.sampling_population,
                }
            }
            SamplingAlgorithm::Probabilistic => {
                if !(self.sampling_probability > 0.0 && self.sampling_probability <= 1.0) {
                    anyhow::bail!(
                        "--sampling-probability must be in (0, 1], got {}",
                        self.sampling_probability
                    );
                }
                SamplingConfig::Probabilistic {
                    probability: self.sampling_probability,
                }
            }
        })
    }
}

/// Run the IPFIX exporter. Logging is initialized by the caller.
pub fn run(args: ExportArgs) -> Result<()> {
    info!("Configuration:");
    info!("  Interface: {}", args.interface);
    info!(
        "  Collector: {}:{}",
        args.collector_host, args.collector_port
    );
    info!(
        "  Active timeout: {}s, Inactive timeout: {}s",
        args.active_timeout, args.inactive_timeout
    );
    info!("  Template refresh: {}s", args.template_refresh_rate);
    let sampling = args.sampling_config()?;
    info!("  Sampling: {:?}", sampling);
    info!("  Mode: {:?}", args.mode);
    if args.mode == ExportMode::Flows && sampling.effective_rate().is_none() {
        warn!(
            "time-based sampling has no packet-count rate; collectors cannot \
             scale flow volumes back to totals"
        );
    }

    // Initialize components
    let capture_config = capture::CaptureConfig {
        promiscuous: args.promiscuous,
        sampling,
        section_length: (args.mode == ExportMode::Packets).then_some(args.section_length as usize),
    };
    let mut capture = capture::open_capture(args.capture, &args.interface, &capture_config)?;
    let mut exporter = Exporter::new(args.clone())?;
    let mut flow_cache = FlowCache::new(args.active_timeout, args.inactive_timeout);

    // Send initial templates and options
    exporter.send_templates()?;
    exporter.send_options_data()?;

    info!("Starting packet capture and flow export");

    // Set up signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        warn!("Received shutdown signal, flushing flows...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut last_check = Instant::now();
    let check_interval = Duration::from_secs(1);
    let stats_interval = Duration::from_secs(args.stats_interval);
    let mut last_stats = Instant::now();
    let mut report_buf: Vec<PacketReport> = Vec::new();

    while running.load(Ordering::SeqCst) {
        // Capture packets (has 1-second timeout, so loop continues even without
        // packets)
        if let Some(packet_info) = capture.next_packet() {
            match args.mode {
                ExportMode::Flows => {
                    flow_cache.update_flow(
                        packet_info.flow_key,
                        packet_info.packet_size,
                        packet_info.tcp_flags,
                    );
                }
                ExportMode::Packets => {
                    if let Some(section) = packet_info.section {
                        report_buf.push(PacketReport {
                            selection_sequence_id: exporter::SELECTION_SEQUENCE_ID,
                            observation_time: DateTime::from_timestamp_millis(
                                packet_info.observation_time_ms,
                            )
                            .unwrap_or_else(Utc::now),
                            frame_length: packet_info.frame_length.min(u16::MAX as u32) as u16,
                            section,
                        });
                    }
                    if report_buf.len() >= PACKET_REPORT_FLUSH_COUNT {
                        if let Err(e) = exporter.send_packet_reports(&report_buf) {
                            error!("Failed to export packet reports: {}", e);
                        }
                        report_buf.clear();
                    }
                }
            }
        }

        // Periodically flush, check for expired flows, and refresh templates
        if last_check.elapsed() >= check_interval {
            match args.mode {
                ExportMode::Flows => {
                    let expired_flows = flow_cache.check_expired_flows();
                    if !expired_flows.is_empty()
                        && let Err(e) = exporter.send_flows(expired_flows)
                    {
                        error!("Failed to export flows: {}", e);
                    }

                    if flow_cache.len() > 0 {
                        info!("Active flows in cache: {}", flow_cache.len());
                    }
                }
                ExportMode::Packets => {
                    if !report_buf.is_empty() {
                        if let Err(e) = exporter.send_packet_reports(&report_buf) {
                            error!("Failed to export packet reports: {}", e);
                        }
                        report_buf.clear();
                    }

                    // RFC 5476 section 6.5.3: statistics MUST be exported
                    // periodically.
                    if last_stats.elapsed() >= stats_interval {
                        if let Err(e) = exporter.send_stats(capture.stats()) {
                            error!("Failed to send statistics: {}", e);
                        }
                        last_stats = Instant::now();
                    }
                }
            }

            // Check if we need to refresh templates
            if exporter.should_send_template() {
                if let Err(e) = exporter.send_templates() {
                    error!("Failed to send templates: {}", e);
                } else if let Err(e) = exporter.send_options_data() {
                    error!("Failed to send options data: {}", e);
                }
            }

            last_check = Instant::now();
        }
    }

    // Graceful shutdown: flush everything still buffered
    match args.mode {
        ExportMode::Flows => {
            info!("Shutting down, exporting remaining flows...");
            let remaining_flows = flow_cache.export_all();
            if !remaining_flows.is_empty() {
                info!("Exporting {} remaining flows", remaining_flows.len());
                if let Err(e) = exporter.send_flows(remaining_flows) {
                    error!("Failed to export remaining flows: {}", e);
                }
            }
        }
        ExportMode::Packets => {
            info!("Shutting down, exporting remaining packet reports...");
            if let Err(e) = exporter.send_packet_reports(&report_buf) {
                error!("Failed to export remaining packet reports: {}", e);
            }
            if let Err(e) = exporter.send_stats(capture.stats()) {
                error!("Failed to send final statistics: {}", e);
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}
