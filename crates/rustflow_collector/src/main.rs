mod enrich;
mod metrics;
mod output;

use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use enrich::{EnrichmentEngine, parse_enrich_arg};
use output::OutputWriter;
use rustflow::pcap::{NetflowPcapReader, SflowPcapReader};
use rustflow::{
    IERegistry, NetflowPacket, NetflowProcessor, NetflowReadResult, NetflowReader, SflowPacket,
    SflowProcessor, SflowReadResult, SflowReader,
};
use rustflow_core::ipfix::parser::IPFIX_VERSION;
use rustflow_core::netflow_v5::parser::NETFLOW_V5_VERSION;
use rustflow_core::netflow_v9::parser::NETFLOW_V9_VERSION;

#[derive(Parser)]
#[command(name = "rustflow_collector")]
#[command(about = "A flow data collector supporting NetFlow and sFlow protocols")]
struct Cli {
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

    /// Serialization format for output
    #[arg(short, long, value_enum, default_value = "json")]
    serialization: SerializationFormat,

    /// Output file path (stdout if not specified)
    #[arg(short, long)]
    output: Option<String>,

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

    /// Flow enrichment configuration (can be specified multiple times)
    /// Format: type=prefix_lookup,source=file.csv,key=dst_addr,fields=col:
    /// output;col2:output2,reload=10s
    #[arg(long = "enrich")]
    enrich: Vec<String>,
}

#[derive(Clone, ValueEnum)]
enum FlowType {
    Netflow,
    Sflow,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Raw,
    Common,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SerializationFormat {
    Json,
    Csv,
}

fn read_netflow_pcap(
    file_path: &str,
    format: OutputFormat,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    match format {
        OutputFormat::Common => {
            let reader = NetflowPcapReader::open(file_path)
                .expect("Failed to open pcap file")
                .with_ie_registry(ie_registry.clone())
                .with_template_timeout(timeout);

            for result in reader {
                match result {
                    Ok(flow) => {
                        let enriched = enrichment.enrich(&flow);
                        output.write_enriched_flow(&flow, &enriched);
                    }
                    Err(e) => {
                        eprintln!("Error reading flow: {}", e);
                        break;
                    }
                }
            }
        }
        OutputFormat::Raw => {
            // For raw format, we still need to use the low-level parsers
            // to output the original packet structure
            read_netflow_pcap_raw(file_path, ie_registry, timeout, output);
        }
    }
}

fn read_netflow_pcap_raw(
    file_path: &str,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    output: &Arc<OutputWriter>,
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
                if let Ok((src, payload)) = parse_udp_packet(&packet.data) {
                    if let Some(parsed) = processor.parse_raw(src, &payload) {
                        write_netflow_packet_raw(&parsed, output);
                    }
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
fn write_netflow_packet_raw(packet: &NetflowPacket, output: &OutputWriter) {
    match packet {
        NetflowPacket::V5(p) => output.write_raw(p),
        NetflowPacket::V9(p) => output.write_raw(p),
        NetflowPacket::Ipfix(p) => output.write_raw(p),
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

fn read_netflow_socket(
    host: &str,
    port: u16,
    format: OutputFormat,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    metrics: Arc<metrics::Metrics>,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let mut reader = NetflowReader::bind(addr)
        .expect("Failed to bind to socket")
        .with_ie_registry(ie_registry.clone())
        .with_template_timeout(timeout);

    eprintln!(
        "Listening for NetFlow data on {}",
        reader.local_addr().unwrap()
    );

    let mut metrics_cache = metrics::NetflowMetricsCache::new(metrics);

    loop {
        match reader.read_raw() {
            Ok(NetflowReadResult::Packet { len, src, packet }) => {
                let version_label = netflow_version_label(&packet);
                let flow_count = netflow_flow_count(&packet);

                metrics_cache.record_packet(src, version_label, len, flow_count);

                match format {
                    OutputFormat::Raw => {
                        write_netflow_packet_raw(&packet, output);
                    }
                    OutputFormat::Common => {
                        let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let flows =
                            reader
                                .processor()
                                .convert_to_flows(src, &packet, time_received_ns);
                        for flow in flows {
                            let enriched = enrichment.enrich(&flow);
                            output.write_enriched_flow(&flow, &enriched);
                        }
                    }
                }

                let processor = reader.processor();
                metrics_cache
                    .metrics()
                    .active_exporters
                    .with_label_values(&[metrics::LABEL_NETFLOW_V9])
                    .set(processor.v9_parsers.len() as f64);
                metrics_cache
                    .metrics()
                    .active_exporters
                    .with_label_values(&[metrics::LABEL_IPFIX])
                    .set(processor.ipfix_parsers.len() as f64);
            }
            Ok(NetflowReadResult::ParseError { len, src, version }) => {
                if let Some(version) = version {
                    if let Some(label) = netflow_version_to_label(version) {
                        metrics_cache.record_parse_error(src, label, len);
                    } else {
                        metrics_cache.record_unknown_version(src, len);
                    }
                }
            }
            Ok(NetflowReadResult::Timeout) => {
                // No data available - continue
            }
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn read_sflow_pcap(
    file_path: &str,
    format: OutputFormat,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    match format {
        OutputFormat::Common => {
            let reader = SflowPcapReader::open(file_path).expect("Failed to open pcap file");

            for result in reader {
                match result {
                    Ok(flow) => {
                        let enriched = enrichment.enrich(&flow);
                        output.write_enriched_flow(&flow, &enriched);
                    }
                    Err(e) => {
                        eprintln!("Error reading flow: {}", e);
                        break;
                    }
                }
            }
        }
        OutputFormat::Raw => {
            read_sflow_pcap_raw(file_path, output);
        }
    }
}

fn read_sflow_pcap_raw(file_path: &str, output: &Arc<OutputWriter>) {
    use pcap_file::pcap::PcapReader;
    use rustflow_core::common::utils::parse_udp_packet;

    let file = std::fs::File::open(file_path).expect("Failed to open pcap file");
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");
    let mut processor = SflowProcessor::new();

    while let Some(pkt) = reader.next_packet() {
        match pkt {
            Ok(packet) => {
                if let Ok((_src, payload)) = parse_udp_packet(&packet.data) {
                    if let Some(parsed) = processor.parse_raw(&payload) {
                        write_sflow_packet_raw(&parsed, output);
                    }
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
fn write_sflow_packet_raw(packet: &SflowPacket, output: &OutputWriter) {
    match packet {
        SflowPacket::V5(p) => output.write_raw(p),
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
    format: OutputFormat,
    metrics: Arc<metrics::Metrics>,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let mut reader = SflowReader::bind(addr).expect("Failed to bind to socket");

    eprintln!(
        "Listening for sFlow data on {}",
        reader.local_addr().unwrap()
    );

    let mut metrics_cache = metrics::SflowMetricsCache::new(metrics);

    loop {
        match reader.read_raw() {
            Ok(SflowReadResult::Packet { len, src, packet }) => {
                let flow_count = sflow_flow_count(&packet);
                metrics_cache.record_packet(src, len, flow_count);

                match format {
                    OutputFormat::Raw => {
                        write_sflow_packet_raw(&packet, output);
                    }
                    OutputFormat::Common => {
                        let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let flows = SflowProcessor::convert_to_flows(&packet, time_received_ns);
                        for flow in flows {
                            let enriched = enrichment.enrich(&flow);
                            output.write_enriched_flow(&flow, &enriched);
                        }
                    }
                }
            }
            Ok(SflowReadResult::ParseError { len, src, version }) => {
                if let Some(version) = version {
                    if version == 5 {
                        metrics_cache.record_parse_error(src, len);
                    } else {
                        metrics_cache.record_unknown_version(src, len);
                    }
                }
            }
            Ok(SflowReadResult::Timeout) => {
                // No data available - continue
            }
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let mut ie_registry = IERegistry::new_with_iana_elements();
    if let Some(ref path) = cli.ie_mapping {
        match ie_registry.load_from_csv(path) {
            Ok(count) => eprintln!("Loaded {} custom IE definitions from {}", count, path),
            Err(e) => {
                eprintln!("Failed to load IE mappings from {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // Parse and build enrichment engine
    let mut enrichment_engine = EnrichmentEngine::new();
    for enrich_arg in &cli.enrich {
        match parse_enrich_arg(enrich_arg) {
            Ok(config) => {
                let source = config.source_file.display().to_string();
                match enrichment_engine.add(config) {
                    Ok(count) => eprintln!("Loaded {} prefix entries from {}", count, source),
                    Err(e) => {
                        eprintln!("Failed to load enrichment from {}: {}", source, e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Invalid --enrich argument: {}", e);
                std::process::exit(1);
            }
        }
    }
    let enrichment_engine = Arc::new(enrichment_engine);

    let output = Arc::new(
        OutputWriter::new(
            cli.output.as_deref(),
            cli.serialization,
            enrichment_engine.output_fields(),
        )
        .expect("Failed to create output writer"),
    );

    let timeout = std::time::Duration::from_secs(cli.template_timeout);

    match (&cli.flow_type, &cli.pcap, &cli.port) {
        (FlowType::Netflow, Some(path), _) => read_netflow_pcap(
            path,
            cli.format,
            &ie_registry,
            timeout,
            &output,
            &enrichment_engine,
        ),
        (FlowType::Netflow, None, Some(port)) => {
            let metrics = Arc::new(metrics::Metrics::new());
            let _metrics_handle = metrics::start_metrics_server(
                Arc::clone(&metrics),
                &cli.metrics_host,
                cli.metrics_port,
            );
            read_netflow_socket(
                &cli.host,
                *port,
                cli.format,
                &ie_registry,
                timeout,
                Arc::clone(&metrics),
                &output,
                &enrichment_engine,
            )
        }
        (FlowType::Sflow, Some(path), _) => {
            read_sflow_pcap(path, cli.format, &output, &enrichment_engine)
        }
        (FlowType::Sflow, None, Some(port)) => {
            let metrics = Arc::new(metrics::Metrics::new());
            let _metrics_handle = metrics::start_metrics_server(
                Arc::clone(&metrics),
                &cli.metrics_host,
                cli.metrics_port,
            );
            read_sflow_socket(
                &cli.host,
                *port,
                cli.format,
                Arc::clone(&metrics),
                &output,
                &enrichment_engine,
            )
        }
        (_, None, None) => {
            eprintln!("Error: Either --pcap or --port must be specified");
            std::process::exit(1);
        }
    }
}
