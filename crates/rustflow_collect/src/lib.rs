mod args;
mod enrich;
mod metrics;
mod protocol;
mod sink;
mod source;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use args::CollectArgs;
use args::FlowType;
use enrich::{EnrichmentConfig, EnrichmentEngine};
use protocol::Protocol;
use rustflow::IERegistry;
use sink::OutputFormat;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, Pipeline};
use source::{Datagram, Source};

/// The socket source checks this between reads to stop ingestion before
/// draining.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn collect<P: Protocol>(
    source: &mut dyn Source,
    protocol: &mut P,
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    output: &mut Pipeline,
) {
    let mut exporters = metrics::ExporterMetrics::new(metrics, P::FAMILY);

    loop {
        match source.next() {
            Datagram::Packet {
                src,
                payload,
                time_received_ns,
            } => match protocol.parse(src, payload) {
                Some(packet) => {
                    exporters.record_packet(
                        src,
                        P::version_label(&packet),
                        payload.len(),
                        P::flow_count(&packet),
                    );
                    match format {
                        OutputFormat::Raw => P::push_raw(&packet, output),
                        OutputFormat::Common => {
                            output.push(protocol.convert(src, &packet, time_received_ns))
                        }
                    }
                    protocol.update_gauges();
                }
                None => match P::version_label_of(payload) {
                    Some(label) => exporters.record_parse_error(src, label, payload.len()),
                    None => exporters.record_unknown_version(src, payload.len()),
                },
            },
            Datagram::Idle => output.flush(),
            Datagram::End => return,
        }
    }
}

/// Open the configured input and start the metrics server for socket
/// collection.
fn open_source<P: Protocol>(cli: &CollectArgs, metrics: &Arc<metrics::Metrics>) -> Box<dyn Source> {
    match (&cli.pcap, cli.port) {
        (Some(path), _) => Box::new(source::Pcap::open(path).unwrap_or_else(|e| {
            eprintln!("Failed to open pcap file {}: {}", path.display(), e);
            std::process::exit(1);
        })),
        (None, Some(port)) => {
            let addr: SocketAddr = format!("{}:{}", cli.host, port).parse().unwrap();
            let socket = source::Socket::bind(addr, CHUNK_FLUSH_TIMEOUT).unwrap_or_else(|e| {
                eprintln!("Failed to bind to {}: {}", addr, e);
                std::process::exit(1);
            });
            eprintln!(
                "Listening for {} data on {}",
                P::NAME,
                socket.local_addr().unwrap()
            );
            // Detached; it serves until the process exits.
            metrics::start_metrics_server(Arc::clone(metrics), &cli.metrics_host, cli.metrics_port);
            Box::new(socket)
        }
        (None, None) => {
            eprintln!("Error: Either --pcap or --port must be specified");
            std::process::exit(1);
        }
    }
}

fn load_ie_registry(path: Option<&Path>) -> IERegistry {
    let mut registry = IERegistry::new_with_iana_elements();
    if let Some(path) = path {
        match registry.load_from_csv(path) {
            Ok(count) => eprintln!(
                "Loaded {} custom IE definitions from {}",
                count,
                path.display()
            ),
            Err(e) => {
                eprintln!("Failed to load IE mappings from {}: {}", path.display(), e);
                std::process::exit(1);
            }
        }
    }
    registry
}

fn load_enrichment(configs: &[EnrichmentConfig], metrics: &metrics::Metrics) -> EnrichmentEngine {
    let mut engine = EnrichmentEngine::new(metrics.enrichment.clone());
    for config in configs {
        let source = config.source.source().display().to_string();
        match engine.add(config.clone()) {
            Ok(count) => eprintln!("Loaded {} rows from {}", count, source),
            Err(e) => {
                eprintln!("Failed to load enrichment from {}: {}", source, e);
                std::process::exit(1);
            }
        }
    }
    engine
}

/// Request socket shutdown on Ctrl-C or SIGTERM so the pipeline can drain
/// and finalize output, including Parquet footers. A second signal forces exit.
fn install_shutdown_handler() {
    if let Err(e) = ctrlc::set_handler(move || {
        if SHUTDOWN.swap(true, Ordering::SeqCst) {
            eprintln!("Forced exit");
            std::process::exit(1);
        }
        eprintln!("Shutting down, draining output...");
    }) {
        eprintln!("Failed to install shutdown handler: {}", e);
    }
}

pub fn run(cli: CollectArgs) {
    let metrics = Arc::new(metrics::Metrics::new());

    let ie_registry = load_ie_registry(cli.ie_mapping.as_deref());
    let enrichment = load_enrichment(&cli.enrich, &metrics);

    let sink = sink::build(
        cli.format,
        &cli.sink_config(),
        enrichment.output_fields().to_vec(),
        &metrics.output,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
    let mut output = Pipeline::spawn(sink, enrichment, metrics.output.clone());

    install_shutdown_handler();

    match cli.flow_type {
        FlowType::Netflow => {
            let mut protocol = protocol::Netflow::new(ie_registry, cli.template_timeout, &metrics);
            let mut source = open_source::<protocol::Netflow>(&cli, &metrics);
            collect(
                &mut *source,
                &mut protocol,
                cli.format,
                metrics,
                &mut output,
            );
        }
        FlowType::Sflow => {
            let mut protocol = protocol::Sflow::new();
            let mut source = open_source::<protocol::Sflow>(&cli, &metrics);
            collect(
                &mut *source,
                &mut protocol,
                cli.format,
                metrics,
                &mut output,
            );
        }
    }

    if let Err(e) = output.drain() {
        eprintln!("Failed to finalize output: {}", e);
        std::process::exit(1);
    }
}
