mod args;
mod enrich;
mod ie_mapping;
mod metrics;
mod sink;
mod source;

use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
pub use args::CollectArgs;
use args::{FlowType, Input};
use enrich::{EnrichmentConfig, EnrichmentEngine};
use log::{error, info, warn};
use rustflow_core::convert::CommonFlow;
use rustflow_core::protocol::information_element::Registry;
use rustflow_core::protocol::{Family, ParseError, Protocol};
use rustflow_core::reader::{Collector, Received, Record};
use sink::OutputFormat;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, EncoderGone, Pipeline, Producer};
use source::{Datagram, Shutdown, Source};

/// What every ingest thread decodes with.
#[derive(Clone)]
struct Decoding {
    format: OutputFormat,
    registry: Registry,
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
    let family = match flow_type {
        FlowType::Netflow => Family::Netflow,
        FlowType::Sflow => Family::Sflow,
    };
    let collector = Collector::new(family, decoding.registry.clone(), decoding.template_timeout);
    let result = collect(
        source,
        collector,
        &decoding.registry,
        decoding.format,
        metrics,
        output,
    );
    // Without an encoder nothing more can be written; stop the other
    // sources too.
    if let Err(EncoderGone) = result {
        shutdown.request();
    }
}

/// The lowercase protocol name metric labels use, such as `netflow_v9`.
fn protocol_name(protocol: Protocol) -> &'static str {
    rustflow_core::convert::FlowType::from(protocol).name()
}

fn collect(
    source: &mut dyn Source,
    mut collector: Collector,
    registry: &Registry,
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    mut output: Producer,
) -> Result<(), EncoderGone> {
    let family = match collector.family() {
        Family::Netflow => "netflow",
        Family::Sflow => "sflow",
    };
    let mut exporters = metrics::ExporterMetrics::new(metrics, family);
    let mut records: Vec<Record> = Vec::new();

    loop {
        let (src, payload, time) = match source.next() {
            Datagram::Packet { src, payload, time } => (src, payload, time),
            Datagram::Idle => {
                output.flush()?;
                continue;
            }
            Datagram::End => return Ok(()),
        };
        exporters.heard_from(src.ip(), time);
        let received = Received {
            exporter: src,
            time: Some(time),
        };

        let mut datagram = || -> Result<(), Failure> {
            match format {
                OutputFormat::Raw => {
                    let packet = collector.parse(received, payload)?;
                    exporters.record_packet(
                        src.ip(),
                        protocol_name(packet.protocol()),
                        payload.len(),
                        packet.record_count(),
                    );
                    output.push_raw(&packet.text(registry), packet.record_count())?;
                }
                OutputFormat::Common => {
                    records.clear();
                    collector.collect(received, payload, &mut records)?;
                    let protocol = Protocol::of(collector.family(), payload)?;
                    exporters.record_packet(
                        src.ip(),
                        protocol_name(protocol),
                        payload.len(),
                        records.len(),
                    );
                    // The record's collection time is in milliseconds; the
                    // flow keeps the receive time whole.
                    let time_received_ns = unix_nanos(time);
                    output.push(|flows| {
                        flows.extend(records.iter().filter(|record| !record.is_options()).map(
                            |record| CommonFlow {
                                time_received_ns,
                                ..CommonFlow::from(record)
                            },
                        ));
                    })?;
                }
            }
            Ok(())
        };
        match datagram() {
            Ok(()) => {}
            Err(Failure::Parse(ParseError::Version(_))) => {
                exporters.record_unknown_version(src.ip(), payload.len());
            }
            Err(Failure::Parse(_)) => match Protocol::of(collector.family(), payload) {
                Ok(protocol) => {
                    exporters.record_parse_error(src.ip(), protocol_name(protocol), payload.len());
                }
                Err(_) => exporters.record_unknown_version(src.ip(), payload.len()),
            },
            Err(Failure::Output(gone)) => return Err(gone),
        }
    }
}

/// Nanoseconds since 1970, as flows carry times; the limit of `i64` for a
/// time past it.
fn unix_nanos(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
    })
}

/// Why a datagram went no further: it did not parse, or the output is gone.
enum Failure {
    Parse(ParseError),
    Output(EncoderGone),
}

impl From<ParseError> for Failure {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<EncoderGone> for Failure {
    fn from(e: EncoderGone) -> Self {
        Self::Output(e)
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
                warn!(
                    "Receive buffer limited to {granted} bytes by the system; raise its limit (net.core.rmem_max on Linux) to get {recv_buffer}"
                );
            }
            info!(
                "Listening for {} data on {} (receive buffer {} bytes)",
                flow_type.name(),
                socket.local_addr()?,
                granted
            );
            Ok(Box::new(socket))
        }
    }
}

fn load_ie_registry(path: Option<&Path>) -> Result<Registry> {
    let mut registry = Registry::iana();
    if let Some(path) = path {
        let count = ie_mapping::load(&mut registry, path)
            .with_context(|| format!("Failed to load IE mappings from {}", path.display()))?;
        info!(
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
        info!("Loaded {count} rows from {source}");
    }
    Ok(engine)
}

/// Request shutdown on Ctrl-C or SIGTERM so the pipeline can drain and
/// finalize output, including Parquet footers. A second signal forces exit.
fn install_shutdown_handler(shutdown: Shutdown) {
    if let Err(e) = ctrlc::set_handler(move || {
        if shutdown.request() {
            warn!("Forced exit");
            std::process::exit(1);
        }
        info!("Shutting down, draining output");
    }) {
        error!("Failed to install the shutdown handler: {e}");
    }
}

pub fn run(cli: CollectArgs) -> Result<()> {
    let sink_config = cli.sink_config()?;
    let metrics = Arc::new(metrics::Metrics::new());
    let shutdown = Shutdown::default();

    let registry = load_ie_registry(cli.ie_mapping.as_deref())?;
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
        registry,
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
