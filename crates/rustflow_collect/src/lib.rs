mod args;
mod enrich;
mod extra_field;
mod field;
mod ie_mapping;
mod metrics;
mod schema;
mod sink;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
pub use args::CollectArgs;
use args::{FlowType, Input};
use enrich::{EnrichmentEngine, parse_enrich_arg};
use log::{error, info, warn};
use rustflow_core::common_flow::ExtraFields;
use rustflow_core::information_element::Registry;
use rustflow_core::reader::{
    NetflowProcessor, PcapSource, Processor, ReadError, Recv, SflowProcessor, Source, UdpSource,
};
use schema::{Column, Schema};
use serde::Serialize;
use sink::OutputFormat;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, EncoderGone, Pipeline, Producer};

/// Ends every input on its next read, so the pipeline can drain:
/// requested on Ctrl-C or SIGTERM, or when the output is gone.
#[derive(Clone, Default)]
struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    /// Returns whether shutdown had already been requested.
    fn request(&self) -> bool {
        self.0.swap(true, Ordering::SeqCst)
    }

    fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// One input's datagrams.
struct Feed {
    flow_type: FlowType,
    source: Box<dyn Source + Send>,
    /// A capture file cannot be read past an error; a socket can.
    ends_on_error: bool,
}

/// What every ingest thread decodes with.
#[derive(Clone)]
struct Decoding {
    format: OutputFormat,
    registry: Registry,
    template_timeout: Duration,
    extra_fields: ExtraFields,
}

fn ingest(
    feed: &mut Feed,
    decoding: &Decoding,
    metrics: Arc<metrics::Metrics>,
    output: Producer,
    shutdown: &Shutdown,
) {
    let result = match feed.flow_type {
        FlowType::Netflow => {
            let mut processor = NetflowProcessor::new(decoding.registry.clone())
                .with_template_ttl(decoding.template_timeout)
                .with_extra_fields(decoding.extra_fields.clone());
            collect(
                feed,
                &mut processor,
                decoding.format,
                metrics,
                output,
                shutdown,
            )
        }
        FlowType::Sflow => collect(
            feed,
            &mut SflowProcessor,
            decoding.format,
            metrics,
            output,
            shutdown,
        ),
    };
    // Without an encoder nothing more can be written; stop the other
    // sources too.
    if let Err(EncoderGone) = result {
        shutdown.request();
    }
}

fn collect<P: Processor>(
    feed: &mut Feed,
    processor: &mut P,
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    mut output: Producer,
    shutdown: &Shutdown,
) -> Result<(), EncoderGone>
where
    P::Packet: Serialize,
{
    let mut exporters = metrics::ExporterMetrics::new(metrics, feed.flow_type.name());

    while !shutdown.requested() {
        let datagram = match feed.source.recv() {
            Ok(Recv::Datagram(datagram)) => datagram,
            Ok(Recv::Timeout) => {
                output.flush()?;
                continue;
            }
            Ok(Recv::End) => break,
            Err(e) => {
                error!("Failed to receive: {e}");
                if feed.ends_on_error {
                    break;
                }
                continue;
            }
        };
        let src = datagram.from.ip();
        let payload = datagram.payload;
        let received_ns = i64::try_from(datagram.received.as_nanosecond()).unwrap_or(i64::MAX);
        exporters.heard_from(src, Some(received_ns));

        let processed = match format {
            OutputFormat::Raw => match processor.parse(src, payload, datagram.now) {
                Ok(packet) => {
                    let summary = P::summary(&packet);
                    output.push_raw(&packet, summary.flows)?;
                    Ok(summary)
                }
                Err(error) => Err(error),
            },
            OutputFormat::Common => output.push(|flows| {
                processor.process(src, payload, datagram.received, datagram.now, flows)
            })?,
        };

        match processed {
            Ok(summary) => exporters.record_packet(src, payload.len(), &summary),
            Err(ReadError::Parse { flow_type, .. }) => {
                exporters.record_parse_error(src, flow_type.name(), payload.len());
            }
            Err(_) => exporters.record_unknown_version(src, payload.len()),
        }
    }
    Ok(())
}

fn open(input: &Input, recv_buffer: usize) -> Result<Feed> {
    match input {
        Input::Pcap { flow_type, path } => {
            let source = PcapSource::open(path)
                .with_context(|| format!("Failed to open pcap file {}", path.display()))?;
            Ok(Feed {
                flow_type: *flow_type,
                source: Box::new(source),
                ends_on_error: true,
            })
        }
        Input::Listen { flow_type, addr } => {
            let source = UdpSource::bind(addr)
                .and_then(|source| source.with_read_timeout(Some(CHUNK_FLUSH_TIMEOUT)))
                .and_then(|source| source.with_recv_buffer_size(recv_buffer))
                .with_context(|| format!("Failed to bind to {addr}"))?;
            let granted = source.recv_buffer_size().unwrap_or(0);
            if granted < recv_buffer {
                warn!(
                    "Receive buffer limited to {granted} bytes by the system; raise its limit (net.core.rmem_max on Linux) to get {recv_buffer}"
                );
            }
            info!(
                "Listening for {} data on {} (receive buffer {} bytes)",
                flow_type.name(),
                source.socket().local_addr()?,
                granted
            );
            Ok(Feed {
                flow_type: *flow_type,
                source: Box::new(source),
                ends_on_error: false,
            })
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

/// Loads the tables of the `--enrich` arguments. Their lookup keys are
/// among `columns`, the flow's fields and the extra fields.
fn load_enrichment(
    args: &[String],
    columns: &[Column],
    metrics: &metrics::Metrics,
) -> Result<EnrichmentEngine> {
    let mut engine = EnrichmentEngine::new(metrics.enrichment.clone());
    for arg in args {
        let config =
            parse_enrich_arg(arg, columns).with_context(|| format!("Invalid --enrich '{arg}'"))?;
        let source = config.source.source().display().to_string();
        let count = engine
            .add(config)
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
    let extra_fields = cli
        .extra_fields
        .iter()
        .map(|arg| arg.resolve(&registry))
        .collect::<Result<Vec<_>>>()?;
    let fields: Vec<_> = extra_fields
        .iter()
        .map(|extra| extra.field.clone())
        .collect();
    let keys = Schema::new(&fields, &[])?;
    let enrichment = load_enrichment(&cli.enrich, keys.columns(), &metrics)?;
    let mut schema = Schema::new(&fields, enrichment.output_fields())?;
    if !cli.fields.is_empty() {
        schema = schema.select(&cli.fields)?;
    }
    if sink_config.serialization == sink::Serialization::Protobuf {
        for line in schema.proto_lines() {
            info!("Add to CommonFlow in rustflow.proto: {line}");
        }
    }

    // Everything that can fail opens before the sink, which creates its
    // first output file right away.
    let feeds = cli
        .input
        .iter()
        .map(|input| open(input, cli.recv_buffer))
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

    let sink = sink::build(&sink_config, schema, &metrics.output)?;
    let output = Pipeline::spawn(sink, enrichment, metrics.output.clone());
    let decoding = Decoding {
        format: cli.format,
        registry,
        template_timeout: cli.template_timeout,
        extra_fields: ExtraFields::new(extra_fields.iter().map(|field| field.id)),
    };

    install_shutdown_handler(shutdown.clone());

    let threads: Vec<_> = feeds
        .into_iter()
        .map(|mut feed| {
            let decoding = decoding.clone();
            let metrics = Arc::clone(&metrics);
            let producer = output.producer();
            let shutdown = shutdown.clone();
            thread::spawn(move || ingest(&mut feed, &decoding, metrics, producer, &shutdown))
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
