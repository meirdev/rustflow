pub mod enrich;
mod metrics;
pub mod sink;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use clap::{Args as ClapArgs, ValueEnum};
use enrich::{EnrichmentEngine, parse_enrich_arg};
use rustflow::pcap::{NetflowPcapReader, SflowPcapReader};
use rustflow::{
    IERegistry, NetflowPacket, NetflowProcessor, NetflowReadResult, NetflowReader, SflowPacket,
    SflowProcessor, SflowReadResult, SflowReader,
};
use rustflow_core::ipfix::parser::IPFIX_VERSION;
use rustflow_core::netflow_v5::parser::NETFLOW_V5_VERSION;
use rustflow_core::netflow_v9::parser::NETFLOW_V9_VERSION;
use sink::pipeline::{CHUNK_FLUSH_TIMEOUT, Pipeline};
use sink::{MAX_PARTITION_LEVEL, OutputFormat, Serialization, SinkConfig};

/// Arguments for the `collect` subcommand.
#[derive(ClapArgs)]
pub struct CollectArgs {
    /// Flow protocol type to collect
    #[arg(short = 't', long, value_enum)]
    flow_type: FlowType,

    /// Path to a pcap file to read instead of listening on a socket
    #[arg(long, conflicts_with_all = ["host", "port"])]
    pcap: Option<String>,

    /// Host address to bind the UDP socket
    #[arg(short = 'H', long, default_value = "0.0.0.0", requires = "port")]
    host: String,

    /// UDP port to listen for flow data
    #[arg(short, long, conflicts_with = "pcap")]
    port: Option<u16>,

    /// Output format: raw (original packet structure) or common (normalized
    /// flow)
    #[arg(short, long, value_enum, default_value = "raw")]
    format: OutputFormat,

    /// Serialization format for output (parquet is Snappy-compressed and
    /// requires `--format common` and `--output`)
    #[arg(short, long, value_enum, default_value = "ndjson")]
    serialization: Serialization,

    /// Output path (stdout if not specified). Without `--interval` this is a
    /// single file; with `--interval` it is the root directory of the
    /// rotated output tree.
    #[arg(short, long)]
    output: Option<String>,

    /// Start a new output file every interval (e.g. `10m`, `1h`).
    /// Requires `--output`, which then names a directory instead of a file.
    #[arg(short = 'i', long, value_name = "DURATION", requires = "output")]
    interval: Option<String>,

    /// Directory partitioning of the output tree: 0 = flat, 1 = `%Y/%m/%d`,
    /// 2 = `%Y/%m/%d/%H`, 3 = `%Y/%m/%d/%H` plus a 5 minute bucket.
    /// Requires `--interval`.
    #[arg(
        short = 'l',
        long,
        default_value = "0",
        value_parser = clap::value_parser!(u8).range(0..=MAX_PARTITION_LEVEL as i64),
        requires = "interval"
    )]
    level: u8,

    /// File name prefix inside the output tree, e.g. `flows` produces
    /// `flows-20240102T150500Z.parquet`. Requires `--interval`.
    #[arg(long, default_value = "flows", requires = "interval")]
    prefix: String,

    /// Host address for Prometheus metrics HTTP server
    #[arg(long, default_value = "0.0.0.0")]
    metrics_host: String,

    /// Port for Prometheus metrics HTTP server
    #[arg(long, default_value = "9090")]
    metrics_port: u16,

    /// Path to a CSV file with custom IE (Information Element) mappings
    #[arg(long)]
    ie_mapping: Option<String>,

    /// Template cache timeout in seconds
    #[arg(long, default_value = "600")]
    template_timeout: u64,

    /// Flow enrichment configuration
    /// Format: type=prefix_lookup|exact,source=file.csv,key_column=col,
    /// fields=<key>@col:output|col2:output2;<key2>@col:output3[,
    /// reload=30s|watch] key_column names the CSV column holding the
    /// prefixes or keys; it does not apply to .mmdb
    #[arg(long = "enrich")]
    enrich: Vec<String>,
}

#[derive(Clone, ValueEnum)]
enum FlowType {
    Netflow,
    Sflow,
}

fn read_netflow_pcap(
    file_path: &str,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    format: OutputFormat,
    output: &mut Pipeline,
) {
    match format {
        OutputFormat::Common => {
            let reader = NetflowPcapReader::open(file_path)
                .expect("Failed to open pcap file")
                .with_ie_registry(ie_registry.clone())
                .with_template_timeout(timeout);

            for result in reader {
                match result {
                    Ok(flow) => output.push([flow]),
                    Err(e) => {
                        eprintln!("Error reading flow: {}", e);
                        break;
                    }
                }
            }
        }
        // For raw format, we still need to use the low-level parsers
        // to output the original packet structure
        OutputFormat::Raw => read_netflow_pcap_raw(file_path, ie_registry, timeout, output),
    }
}

fn read_netflow_pcap_raw(
    file_path: &str,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    output: &mut Pipeline,
) {
    use pcap_file::pcap::PcapReader;
    use rustflow_core::common::utils::parse_udp_packet;

    let file = std::fs::File::open(file_path).expect("Failed to open pcap file");
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");
    let mut processor = NetflowProcessor::new()
        .with_ie_registry(ie_registry.clone())
        .with_template_timeout(timeout);

    while let Some(pkt) = reader.next_packet() {
        match pkt {
            Ok(packet) => {
                if let Some((src, payload)) = parse_udp_packet(&packet.data)
                    && let Some(parsed) = processor.parse_raw(src, &payload)
                {
                    write_netflow_packet_raw(&parsed, output);
                }
            }
            Err(err) => {
                eprintln!("{:#?}", err);
                break;
            }
        }
    }
}

/// Write a raw NetFlow packet to output.
fn write_netflow_packet_raw(packet: &NetflowPacket, output: &mut Pipeline) {
    match packet {
        NetflowPacket::V5(p) => output.push_raw(p),
        NetflowPacket::V9(p) => output.push_raw(p),
        NetflowPacket::Ipfix(p) => output.push_raw(p),
    }
}

/// Get the version label for metrics from a NetflowPacket.
fn netflow_version_label(packet: &NetflowPacket) -> &'static str {
    match packet {
        NetflowPacket::V5(_) => metrics::LABEL_NETFLOW_V5,
        NetflowPacket::V9(_) => metrics::LABEL_NETFLOW_V9,
        NetflowPacket::Ipfix(_) => metrics::LABEL_IPFIX,
    }
}

/// Get the version label for metrics from a raw version number.
/// Returns None for unknown versions.
fn netflow_version_to_label(version: u16) -> Option<&'static str> {
    match version {
        NETFLOW_V5_VERSION => Some(metrics::LABEL_NETFLOW_V5),
        NETFLOW_V9_VERSION => Some(metrics::LABEL_NETFLOW_V9),
        IPFIX_VERSION => Some(metrics::LABEL_IPFIX),
        _ => None,
    }
}

/// Count data records in a NetflowPacket.
fn netflow_flow_count(packet: &NetflowPacket) -> usize {
    use rustflow_core::ipfix::parser::Record as IpfixRecord;
    use rustflow_core::netflow_v9::parser::Record as V9Record;

    match packet {
        NetflowPacket::V5(p) => p.flow_records.len(),
        NetflowPacket::V9(p) => p
            .flow_sets
            .iter()
            .map(|fs| {
                fs.records
                    .iter()
                    .filter(|r| matches!(r, V9Record::Data(_)))
                    .count()
            })
            .sum(),
        NetflowPacket::Ipfix(p) => p
            .sets
            .iter()
            .map(|s| {
                s.records
                    .iter()
                    .filter(|r| matches!(r, IpfixRecord::Data(_)))
                    .count()
            })
            .sum(),
    }
}

/// Set by the signal handler; the ingest loops poll it (their socket read
/// timeout bounds the latency) and exit so the pipeline drains in order.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn read_netflow_socket(
    host: &str,
    port: u16,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    metrics: Arc<metrics::Metrics>,
    format: OutputFormat,
    output: &mut Pipeline,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let mut reader = NetflowReader::bind(addr)
        .expect("Failed to bind to socket")
        .with_ie_registry(ie_registry.clone())
        .with_template_timeout(timeout)
        .with_read_timeout(Some(CHUNK_FLUSH_TIMEOUT))
        .expect("Failed to set read timeout");

    eprintln!(
        "Listening for NetFlow data on {}",
        reader.local_addr().unwrap()
    );

    let v9_exporters = metrics.active_exporters(metrics::LABEL_NETFLOW_V9);
    let ipfix_exporters = metrics.active_exporters(metrics::LABEL_IPFIX);
    let mut exporters = metrics::ExporterMetrics::new(metrics, metrics::LABEL_NETFLOW);

    while !SHUTDOWN.load(Ordering::Relaxed) {
        match reader.read_raw() {
            Ok(NetflowReadResult::Packet { len, src, packet }) => {
                let version_label = netflow_version_label(&packet);
                let flow_count = netflow_flow_count(&packet);

                exporters.record_packet(src, version_label, len, flow_count);

                match format {
                    OutputFormat::Raw => write_netflow_packet_raw(&packet, output),
                    OutputFormat::Common => {
                        let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let flows =
                            reader
                                .processor()
                                .convert_to_flows(src, &packet, time_received_ns);
                        output.push(flows);
                    }
                }

                let processor = reader.processor();
                v9_exporters.set(processor.v9_parsers.len() as i64);
                ipfix_exporters.set(processor.ipfix_parsers.len() as i64);
            }
            Ok(NetflowReadResult::ParseError { len, src, version }) => {
                if let Some(version) = version {
                    if let Some(label) = netflow_version_to_label(version) {
                        exporters.record_parse_error(src, label, len);
                    } else {
                        exporters.record_unknown_version(src, len);
                    }
                }
            }
            Ok(NetflowReadResult::Timeout) => output.flush(),
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn read_sflow_pcap(file_path: &str, format: OutputFormat, output: &mut Pipeline) {
    match format {
        OutputFormat::Common => {
            let reader = SflowPcapReader::open(file_path).expect("Failed to open pcap file");

            for result in reader {
                match result {
                    Ok(flow) => output.push([flow]),
                    Err(e) => {
                        eprintln!("Error reading flow: {}", e);
                        break;
                    }
                }
            }
        }
        OutputFormat::Raw => read_sflow_pcap_raw(file_path, output),
    }
}

fn read_sflow_pcap_raw(file_path: &str, output: &mut Pipeline) {
    use pcap_file::pcap::PcapReader;
    use rustflow_core::common::utils::parse_udp_packet;

    let file = std::fs::File::open(file_path).expect("Failed to open pcap file");
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");
    let mut processor = SflowProcessor::new();

    while let Some(pkt) = reader.next_packet() {
        match pkt {
            Ok(packet) => {
                if let Some((_src, payload)) = parse_udp_packet(&packet.data)
                    && let Some(parsed) = processor.parse_raw(&payload)
                {
                    write_sflow_packet_raw(&parsed, output);
                }
            }
            Err(err) => {
                eprintln!("{:#?}", err);
                break;
            }
        }
    }
}

/// Write a raw sFlow packet to output.
fn write_sflow_packet_raw(packet: &SflowPacket, output: &mut Pipeline) {
    match packet {
        SflowPacket::V5(p) => output.push_raw(p),
    }
}

/// Count flow samples in an sFlow packet.
fn sflow_flow_count(packet: &SflowPacket) -> usize {
    use rustflow_core::sflow_v5::parser::Sample;

    match packet {
        SflowPacket::V5(p) => p
            .samples
            .iter()
            .filter(|s| matches!(s, Sample::Flow(_) | Sample::ExpandedFlow(_)))
            .count(),
    }
}

fn read_sflow_socket(
    host: &str,
    port: u16,
    metrics: Arc<metrics::Metrics>,
    format: OutputFormat,
    output: &mut Pipeline,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let mut reader = SflowReader::bind(addr)
        .expect("Failed to bind to socket")
        .with_read_timeout(Some(CHUNK_FLUSH_TIMEOUT))
        .expect("Failed to set read timeout");

    eprintln!(
        "Listening for sFlow data on {}",
        reader.local_addr().unwrap()
    );

    let mut exporters = metrics::ExporterMetrics::new(metrics, metrics::LABEL_SFLOW);

    while !SHUTDOWN.load(Ordering::Relaxed) {
        match reader.read_raw() {
            Ok(SflowReadResult::Packet { len, src, packet }) => {
                let flow_count = sflow_flow_count(&packet);
                exporters.record_packet(src, metrics::LABEL_SFLOW_V5, len, flow_count);

                match format {
                    OutputFormat::Raw => write_sflow_packet_raw(&packet, output),
                    OutputFormat::Common => {
                        let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let flows = SflowProcessor::convert_to_flows(&packet, time_received_ns);
                        output.push(flows);
                    }
                }
            }
            Ok(SflowReadResult::ParseError { len, src, version }) => {
                if let Some(version) = version {
                    if version == 5 {
                        exporters.record_parse_error(src, metrics::LABEL_SFLOW_V5, len);
                    } else {
                        exporters.record_unknown_version(src, len);
                    }
                }
            }
            Ok(SflowReadResult::Timeout) => output.flush(),
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn sink_config(cli: &CollectArgs) -> SinkConfig {
    let interval = cli.interval.as_deref().map(|value| {
        duration_str::parse(value.trim()).unwrap_or_else(|e| {
            eprintln!("Invalid --interval value '{}': {}", value, e);
            std::process::exit(1);
        })
    });
    SinkConfig {
        path: cli.output.as_deref().map(PathBuf::from),
        serialization: cli.serialization,
        interval,
        level: cli.level,
        prefix: cli.prefix.clone(),
    }
}

/// The IANA elements plus the `--ie-mapping` file, if any.
fn load_ie_registry(path: Option<&str>) -> IERegistry {
    let mut registry = IERegistry::new_with_iana_elements();
    if let Some(path) = path {
        match registry.load_from_csv(path) {
            Ok(count) => eprintln!("Loaded {} custom IE definitions from {}", count, path),
            Err(e) => {
                eprintln!("Failed to load IE mappings from {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }
    registry
}

/// The tables named by `--enrich`, loaded; any failure exits.
fn load_enrichment(cli: &CollectArgs, metrics: &metrics::Metrics) -> EnrichmentEngine {
    let mut engine = EnrichmentEngine::new(metrics.enrichment.clone());
    for arg in &cli.enrich {
        let config = parse_enrich_arg(arg).unwrap_or_else(|e| {
            eprintln!("Invalid --enrich argument: {}", e);
            std::process::exit(1);
        });
        let source = config.source.source().display().to_string();
        match engine.add(config) {
            Ok(count) => eprintln!("Loaded {} rows from {}", count, source),
            Err(e) => {
                eprintln!("Failed to load enrichment from {}: {}", source, e);
                std::process::exit(1);
            }
        }
    }
    engine
}

/// Graceful shutdown on Ctrl-C / SIGTERM: flag the ingest loop to stop,
/// which drains the pipeline and finalizes the output (a parquet file is
/// unreadable until its footer is written). A second signal forces exit,
/// so a stuck drain can never trap the operator.
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

/// Run the flow collector.
pub fn run(cli: CollectArgs) {
    let metrics = Arc::new(metrics::Metrics::new());
    let ie_registry = load_ie_registry(cli.ie_mapping.as_deref());
    let enrichment = load_enrichment(&cli, &metrics);

    let sink = sink::build(
        cli.format,
        &sink_config(&cli),
        enrichment.output_fields().to_vec(),
        &metrics.output,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
    let mut output = Pipeline::spawn(sink, enrichment, metrics.output.clone());

    install_shutdown_handler();
    let timeout = std::time::Duration::from_secs(cli.template_timeout);

    match (&cli.flow_type, &cli.pcap, &cli.port) {
        (FlowType::Netflow, Some(path), _) => {
            read_netflow_pcap(path, &ie_registry, timeout, cli.format, &mut output)
        }
        (FlowType::Netflow, None, Some(port)) => {
            let _metrics_handle = metrics::start_metrics_server(
                Arc::clone(&metrics),
                &cli.metrics_host,
                cli.metrics_port,
            );
            read_netflow_socket(
                &cli.host,
                *port,
                &ie_registry,
                timeout,
                Arc::clone(&metrics),
                cli.format,
                &mut output,
            )
        }
        (FlowType::Sflow, Some(path), _) => read_sflow_pcap(path, cli.format, &mut output),
        (FlowType::Sflow, None, Some(port)) => {
            let _metrics_handle = metrics::start_metrics_server(
                Arc::clone(&metrics),
                &cli.metrics_host,
                cli.metrics_port,
            );
            read_sflow_socket(
                &cli.host,
                *port,
                Arc::clone(&metrics),
                cli.format,
                &mut output,
            )
        }
        (_, None, None) => {
            eprintln!("Error: Either --pcap or --port must be specified");
            std::process::exit(1);
        }
    }

    // Socket modes return here after a graceful shutdown; pcap modes when the
    // file is exhausted.
    if let Err(e) = output.drain() {
        eprintln!("Failed to finalize output: {}", e);
        std::process::exit(1);
    }
}
