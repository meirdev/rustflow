mod args;
mod enrich;
mod metrics;
mod protocol;
mod sink;
mod source;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub use args::CollectArgs;
use args::{FlowType, Listener};
use enrich::{EnrichmentConfig, EnrichmentEngine};
use protocol::Protocol;
use rustflow::IERegistry;
use sink::OutputFormat;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, Pipeline, Producer};
use source::{Datagram, Source};

/// The socket source checks this between reads to stop ingestion before
/// draining.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// What every ingest thread decodes with.
#[derive(Clone)]
struct Decoding {
    format: OutputFormat,
    ie_registry: IERegistry,
    template_timeout: Duration,
}

fn ingest(
    flow_type: FlowType,
    source: &mut dyn Source,
    decoding: &Decoding,
    metrics: Arc<metrics::Metrics>,
    output: Producer,
) {
    match flow_type {
        FlowType::Netflow => {
            let mut protocol = protocol::Netflow::new(
                decoding.ie_registry.clone(),
                decoding.template_timeout,
                &metrics,
            );
            collect(source, &mut protocol, decoding.format, metrics, output);
        }
        FlowType::Sflow => {
            let mut protocol = protocol::Sflow::new();
            collect(source, &mut protocol, decoding.format, metrics, output);
        }
    }
}

fn collect<P: Protocol>(
    source: &mut dyn Source,
    protocol: &mut P,
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    mut output: Producer,
) {
    let mut exporters = metrics::ExporterMetrics::new(metrics, P::FAMILY);

    loop {
        let (src, payload, time_received_ns) = match source.next() {
            Datagram::Packet {
                src,
                payload,
                time_received_ns,
            } => (src, payload, time_received_ns),
            Datagram::Idle => {
                output.flush();
                continue;
            }
            Datagram::End => return,
        };

        let Some(packet) = protocol.parse(src, payload) else {
            match P::version_label_of(payload) {
                Some(label) => exporters.record_parse_error(src, label, payload.len()),
                None => exporters.record_unknown_version(src, payload.len()),
            }
            continue;
        };

        exporters.record_packet(
            src,
            P::version_label(&packet),
            payload.len(),
            P::flow_count(&packet),
        );

        match format {
            OutputFormat::Raw => P::push_raw(&packet, &mut output),
            OutputFormat::Common => output.push(protocol.convert(src, &packet, time_received_ns)),
        }

        protocol.update_gauges();
    }
}

fn bind(listener: &Listener, recv_buffer: usize) -> source::Socket {
    let socket = source::Socket::bind(listener.addr, CHUNK_FLUSH_TIMEOUT, recv_buffer)
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {}: {}", listener.addr, e);
            std::process::exit(1);
        });
    let granted = socket.recv_buffer_size().unwrap_or(0);
    if granted < recv_buffer {
        eprintln!(
            "Warning: receive buffer limited to {} bytes by the system; raise its limit (net.core.rmem_max on Linux) to get {}",
            granted, recv_buffer
        );
    }
    eprintln!(
        "Listening for {} data on {} (receive buffer {} bytes)",
        listener.flow_type.name(),
        socket.local_addr().unwrap(),
        granted
    );
    socket
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
    let output = Pipeline::spawn(sink, enrichment, metrics.output.clone());
    let decoding = Decoding {
        format: cli.format,
        ie_registry,
        template_timeout: cli.template_timeout,
    };

    install_shutdown_handler();

    match &cli.pcap {
        Some(pcap) => {
            let mut source = source::Pcap::open(&pcap.path).unwrap_or_else(|e| {
                eprintln!("Failed to open pcap file {}: {}", pcap.path.display(), e);
                std::process::exit(1);
            });
            ingest(
                pcap.flow_type,
                &mut source,
                &decoding,
                metrics,
                output.producer(),
            );
        }
        None => {
            // Bind everything first, so a bad address fails before any
            // thread starts.
            let sockets: Vec<_> = cli
                .listen
                .iter()
                .map(|listener| (listener.flow_type, bind(listener, cli.recv_buffer)))
                .collect();
            // Detached; it serves until the process exits.
            metrics::start_metrics_server(Arc::clone(&metrics), cli.metrics_host, cli.metrics_port);
            let threads: Vec<_> = sockets
                .into_iter()
                .map(|(flow_type, mut socket)| {
                    let decoding = decoding.clone();
                    let metrics = Arc::clone(&metrics);
                    let producer = output.producer();
                    thread::spawn(move || {
                        ingest(flow_type, &mut socket, &decoding, metrics, producer)
                    })
                })
                .collect();
            for thread in threads {
                if thread.join().is_err() {
                    eprintln!("An ingest thread panicked");
                }
            }
        }
    }

    if let Err(e) = output.drain() {
        eprintln!("Failed to finalize output: {}", e);
        std::process::exit(1);
    }
}
