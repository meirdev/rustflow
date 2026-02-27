mod capture;
mod config;
mod exporter;
mod flow;
mod ipfix;

use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use capture::PacketCapture;
use config::Config;
use exporter::Exporter;
use flow::FlowCache;

#[derive(Parser, Debug)]
#[command(name = "rustflow_exporter")]
#[command(about = "IPFIX exporter for network flow data", long_about = None)]
struct Args {
    /// Network interface to capture from
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Collector host address
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    collector_host: String,

    /// Collector port
    #[arg(short = 'p', long, default_value = "4739")]
    collector_port: u16,

    /// Observation domain ID
    #[arg(long, default_value = "1")]
    observation_domain_id: u32,

    /// Active flow timeout in seconds
    #[arg(long, default_value = "60")]
    active_timeout: u64,

    /// Inactive flow timeout in seconds
    #[arg(long, default_value = "15")]
    inactive_timeout: u64,

    /// Template refresh rate in seconds
    #[arg(long, default_value = "300")]
    template_refresh: u64,

    /// Sampling packet interval
    #[arg(long, default_value = "1")]
    sampling_interval: u32,

    /// Enable promiscuous mode
    #[arg(long)]
    promiscuous: bool,
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Build configuration from CLI arguments
    let config = Config {
        exporter: config::ExporterConfig {
            collector_host: args.collector_host,
            collector_port: args.collector_port,
            observation_domain_id: args.observation_domain_id,
        },
        capture: config::CaptureConfig {
            interface: args.interface,
            promiscuous: args.promiscuous,
        },
        flow: config::FlowConfig {
            active_timeout: args.active_timeout,
            inactive_timeout: args.inactive_timeout,
        },
        template: config::TemplateConfig {
            refresh_rate: args.template_refresh,
        },
        options: config::OptionsConfig {
            sampling_packet_interval: args.sampling_interval,
        },
    };

    info!("Configuration:");
    info!("  Interface: {}", config.capture.interface);
    info!(
        "  Collector: {}:{}",
        config.exporter.collector_host, config.exporter.collector_port
    );
    info!(
        "  Active timeout: {}s, Inactive timeout: {}s",
        config.flow.active_timeout, config.flow.inactive_timeout
    );
    info!(
        "  Template refresh: {}s",
        config.template.refresh_rate
    );
    info!(
        "  Sampling interval: 1 out of {} packets",
        config.options.sampling_packet_interval
    );

    // Initialize components
    let mut capture = PacketCapture::new(&config.capture.interface, config.capture.promiscuous)?;
    let mut exporter = Exporter::new(config.clone())?;
    let mut flow_cache = FlowCache::new(config.flow.active_timeout, config.flow.inactive_timeout);

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
    }).expect("Error setting Ctrl-C handler");

    let mut last_check = Instant::now();
    let check_interval = Duration::from_secs(1);

    while running.load(Ordering::SeqCst) {
        // Capture packets (has 1-second timeout, so loop continues even without packets)
        if let Some(packet_info) = capture.next_packet() {
            flow_cache.update_flow(
                packet_info.flow_key,
                packet_info.packet_size,
                packet_info.tcp_flags,
            );
        }

        // Periodically check for expired flows and template refresh
        // Note: This runs every second due to pcap timeout, even without packets
        if last_check.elapsed() >= check_interval {
            // Check for expired flows
            let expired_flows = flow_cache.check_expired_flows();
            if !expired_flows.is_empty() {
                if let Err(e) = exporter.send_flows(expired_flows) {
                    error!("Failed to export flows: {}", e);
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

            // Log current cache size
            if flow_cache.len() > 0 {
                info!("Active flows in cache: {}", flow_cache.len());
            }

            last_check = Instant::now();
        }
    }

    // Graceful shutdown: flush all remaining flows
    info!("Shutting down, exporting remaining flows...");
    let remaining_flows = flow_cache.export_all();
    if !remaining_flows.is_empty() {
        info!("Exporting {} remaining flows", remaining_flows.len());
        if let Err(e) = exporter.send_flows(remaining_flows) {
            error!("Failed to export remaining flows: {}", e);
        }
    }

    info!("Shutdown complete");
    Ok(())
}
