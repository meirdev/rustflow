mod args;
mod enrich;
mod metrics;
mod protocol;
mod sink;
mod source;

use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
pub use args::CollectArgs;
use args::{FlowType, Input};
use enrich::{EnrichmentConfig, EnrichmentEngine};
use protocol::Protocol;
use rustflow::IERegistry;
use sink::OutputFormat;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, EncoderGone, Pipeline, Producer};
use source::{Datagram, Shutdown, Source};

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
    shutdown: &Shutdown,
) {
    let result = match flow_type {
        FlowType::Netflow => {
            let mut protocol =
                protocol::Netflow::new(decoding.ie_registry.clone(), decoding.template_timeout);
            collect(source, &mut protocol, decoding.format, metrics, output)
        }
        FlowType::Sflow => {
            let mut protocol = protocol::Sflow::new();
            collect(source, &mut protocol, decoding.format, metrics, output)
        }
    };
    // Without an encoder nothing more can be written; stop the other
    // sources too.
    if let Err(EncoderGone) = result {
        shutdown.request();
    }
}

fn collect<P: Protocol>(
    source: &mut dyn Source,
    protocol: &mut P,
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    mut output: Producer,
) -> Result<(), EncoderGone> {
    let mut exporters = metrics::ExporterMetrics::new(metrics, P::FAMILY);

    loop {
        let (src, payload, time_received_ns) = match source.next() {
            Datagram::Packet {
                src,
                payload,
                time_received_ns,
            } => (src, payload, time_received_ns),
            Datagram::Idle => {
                output.flush()?;
                continue;
            }
            Datagram::End => return Ok(()),
        };
        exporters.heard_from(src, time_received_ns);

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
            OutputFormat::Raw => P::push_raw(&packet, &mut output)?,
            OutputFormat::Common => {
                output.push(protocol.convert(src, &packet, time_received_ns))?
            }
        }
    }
}

fn open(input: &Input, recv_buffer: usize, shutdown: &Shutdown) -> Result<Box<dyn Source + Send>> {
    match input {
        Input::Pcap { path, .. } => {
            let source = source::Pcap::open(path, shutdown.clone())
                .with_context(|| format!("Failed to open pcap file {}", path.display()))?;
            Ok(Box::new(source))
        }
        Input::Listen { flow_type, addr } => {
            let socket =
                source::Socket::bind(*addr, CHUNK_FLUSH_TIMEOUT, recv_buffer, shutdown.clone())
                    .with_context(|| format!("Failed to bind to {addr}"))?;
            let granted = socket.recv_buffer_size().unwrap_or(0);
            if granted < recv_buffer {
                eprintln!(
                    "Warning: receive buffer limited to {} bytes by the system; raise its limit (net.core.rmem_max on Linux) to get {}",
                    granted, recv_buffer
                );
            }
            eprintln!(
                "Listening for {} data on {} (receive buffer {} bytes)",
                flow_type.name(),
                socket.local_addr()?,
                granted
            );
            Ok(Box::new(socket))
        }
    }
}

fn load_ie_registry(path: Option<&Path>) -> Result<IERegistry> {
    let mut registry = IERegistry::new_with_iana_elements();
    if let Some(path) = path {
        let count = registry
            .load_from_csv(path)
            .with_context(|| format!("Failed to load IE mappings from {}", path.display()))?;
        eprintln!(
            "Loaded {} custom IE definitions from {}",
            count,
            path.display()
        );
    }
    Ok(registry)
}

fn load_enrichment(
    configs: &[EnrichmentConfig],
    metrics: &metrics::Metrics,
) -> Result<EnrichmentEngine> {
    let mut engine = EnrichmentEngine::new(metrics.enrichment.clone());
    for config in configs {
        let source = config.source.source().display().to_string();
        let count = engine
            .add(config.clone())
            .with_context(|| format!("Failed to load enrichment from {source}"))?;
        eprintln!("Loaded {} rows from {}", count, source);
    }
    Ok(engine)
}

/// Request shutdown on Ctrl-C or SIGTERM so the pipeline can drain and
/// finalize output, including Parquet footers. A second signal forces exit.
fn install_shutdown_handler(shutdown: Shutdown) {
    if let Err(e) = ctrlc::set_handler(move || {
        if shutdown.request() {
            eprintln!("Forced exit");
            std::process::exit(1);
        }
        eprintln!("Shutting down, draining output...");
    }) {
        eprintln!("Failed to install shutdown handler: {}", e);
    }
}

pub fn run(cli: CollectArgs) -> Result<()> {
    let sink_config = cli.sink_config()?;
    let metrics = Arc::new(metrics::Metrics::new());
    let shutdown = Shutdown::default();

    let ie_registry = load_ie_registry(cli.ie_mapping.as_deref())?;
    let enrichment = load_enrichment(&cli.enrich, &metrics)?;

    // Everything that can fail opens before the sink, which creates its
    // first output file right away.
    let sources = cli
        .input
        .iter()
        .map(|input| Ok((input.flow_type(), open(input, cli.recv_buffer, &shutdown)?)))
        .collect::<Result<Vec<_>>>()?;
    if cli
        .input
        .iter()
        .any(|input| matches!(input, Input::Listen { .. }))
    {
        // Detached; it serves until the process exits.
        metrics::start_metrics_server(Arc::clone(&metrics), cli.metrics_host, cli.metrics_port)
            .context("Failed to start the metrics server")?;
    }

    let sink = sink::build(
        &sink_config,
        enrichment.output_fields().to_vec(),
        &metrics.output,
    )?;
    let output = Pipeline::spawn(sink, enrichment, metrics.output.clone());
    let decoding = Decoding {
        format: cli.format,
        ie_registry,
        template_timeout: cli.template_timeout,
    };

    install_shutdown_handler(shutdown.clone());

    let threads: Vec<_> = sources
        .into_iter()
        .map(|(flow_type, mut source)| {
            let decoding = decoding.clone();
            let metrics = Arc::clone(&metrics);
            let producer = output.producer();
            let shutdown = shutdown.clone();
            thread::spawn(move || {
                ingest(
                    flow_type,
                    &mut *source,
                    &decoding,
                    metrics,
                    producer,
                    &shutdown,
                )
            })
        })
        .collect();
    let mut panicked = false;
    for thread in threads {
        panicked |= thread.join().is_err();
    }

    output.drain().context("Failed to finalize output")?;
    if panicked {
        bail!("An ingest thread panicked");
    }
    Ok(())
}
