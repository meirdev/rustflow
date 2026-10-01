mod args;
mod capture;
mod exporter;
mod flow;
mod ipfix;
mod meter;
mod sampler;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
pub use args::ExportArgs;
use exporter::Exporter;
use log::{error, info, warn};
use meter::Meter;

pub fn run(args: ExportArgs) -> Result<()> {
    info!("Configuration:");
    info!(
        "  Interface: {} ({:?} capture)",
        args.interface, args.capture
    );
    info!(
        "  Collector: {}:{}",
        args.collector_host, args.collector_port
    );
    info!(
        "  Active timeout: {}s, Inactive timeout: {}s",
        args.active_timeout, args.inactive_timeout
    );
    info!("  Template refresh: {}s", args.template_refresh_rate);
    info!("  Sampling: {}", args.sampling());
    info!("  Mode: {:?}", args.mode);

    let mut exporter = Exporter::new(args.clone())?;
    let mut capture = capture::open(args.capture, &args.interface, args.promiscuous)?;
    let mut meter = Meter::new(
        &args,
        capture.link(),
        exporter.local_addr()?,
        exporter.collector_addr(),
    );

    exporter.send_templates()?;
    exporter.send_options_data()?;

    info!("Starting packet capture and export");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        warn!("Received shutdown signal, flushing...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut last_check = Instant::now();
    let check_interval = Duration::from_secs(1);

    while running.load(Ordering::SeqCst) {
        // Capture packets (has 1-second timeout, so loop continues even without
        // packets)
        if let Some(frame) = capture.next_frame() {
            meter.observe(&frame);
        }

        let tick = last_check.elapsed() >= check_interval;
        if (tick || meter.is_full())
            && let Err(e) = exporter.send(meter.take_due())
        {
            error!("Failed to export: {}", e);
        }

        if tick {
            if exporter.should_send_template() {
                if let Err(e) = exporter.send_templates() {
                    error!("Failed to send templates: {}", e);
                } else if let Err(e) = exporter.send_options_data() {
                    error!("Failed to send options data: {}", e);
                }
            }

            if meter.active_flows() > 0 {
                info!("Active flows in cache: {}", meter.active_flows());
            }

            last_check = Instant::now();
        }
    }

    info!("Shutting down, exporting what is left...");
    if let Err(e) = exporter.send(meter.take_all()) {
        error!("Failed to export: {}", e);
    }

    info!("Shutdown complete");
    Ok(())
}
