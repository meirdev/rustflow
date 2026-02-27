mod enrich;
mod metrics;
mod output;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use enrich::{parse_enrich_arg, EnrichmentEngine};
use output::OutputWriter;
use pcap_file::pcap::PcapReader;
use rustc_hash::FxHashMap;
use rustflow_core::common::common_flow::{
    IpfixContext, NetFlowV5Context, NetFlowV9Context, SFlowV5Context, SamplingRateCache,
    extract_ipfix_sampling_rate, extract_v9_sampling_rate,
};
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::common::utils::parse_udp_packet;
use rustflow_core::ipfix::parser::{IPFIX_VERSION, IpfixParser, Record as IpfixRecord};
use rustflow_core::netflow_v5::parser::{NETFLOW_V5_VERSION, NetFlowV5Parser};
use rustflow_core::netflow_v9::parser::{NETFLOW_V9_VERSION, NetflowV9Parser, Record as V9Record};
use rustflow_core::sflow_v5::parser::{SFLOW_V5_VERSION, Sample, SflowV5Parser};

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
    /// Format: type=prefix_lookup,source=file.csv,key=dst_addr,match=longest,fields=col:output;col2:output2,reload=10s
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

fn pcap_ts_to_nanos(ts: std::time::Duration) -> i64 {
    ts.as_nanos() as i64
}

fn read_netflow_pcap(
    file_path: &str,
    format: OutputFormat,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let file = std::fs::File::open(file_path).expect("Failed to open pcap file");
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");

    let mut v5_parser = NetFlowV5Parser::default();
    let mut v9_parsers: FxHashMap<IpAddr, NetflowV9Parser> = FxHashMap::default();
    let mut ipfix_parsers: FxHashMap<IpAddr, IpfixParser> = FxHashMap::default();
    let mut sampling_cache = SamplingRateCache::default();
    let ie_registry = ie_registry.clone();

    while let Some(pkt) = reader.next_packet() {
        match pkt {
            Ok(packet) => {
                let time_received_ns = Some(pcap_ts_to_nanos(packet.timestamp));
                if let Ok((src, payload)) = parse_udp_packet(&packet.data) {
                    parse_netflow(
                        &mut v5_parser,
                        &mut v9_parsers,
                        &mut ipfix_parsers,
                        &mut sampling_cache,
                        &ie_registry,
                        timeout,
                        src,
                        &payload,
                        format,
                        time_received_ns,
                        None,
                        &src.to_string(),
                        output,
                        enrichment,
                    );
                }
            }
            Err(err) => {
                eprintln!("{:#?}", err);
                break;
            }
        }
    }
}

fn read_netflow_socket(
    host: &str,
    port: u16,
    format: OutputFormat,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    metrics: &Arc<metrics::Metrics>,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let socket = UdpSocket::bind(addr).expect("Failed to bind to socket");
    println!("Listening for NetFlow data on {}", addr);

    let mut buf = [0u8; 65535];
    let mut v5_parser = NetFlowV5Parser::default();
    let mut v9_parsers: FxHashMap<IpAddr, NetflowV9Parser> = FxHashMap::default();
    let mut ipfix_parsers: FxHashMap<IpAddr, IpfixParser> = FxHashMap::default();
    let mut sampling_cache = SamplingRateCache::default();
    let ie_registry = ie_registry.clone();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let src_ip = src_addr.ip().to_string();

                metrics
                    .packets_received_total
                    .with_label_values(&["netflow", &src_ip])
                    .inc();
                metrics
                    .bytes_received_total
                    .with_label_values(&[&src_ip])
                    .inc_by(len as f64);

                let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let payload = &buf[..len];
                parse_netflow(
                    &mut v5_parser,
                    &mut v9_parsers,
                    &mut ipfix_parsers,
                    &mut sampling_cache,
                    &ie_registry,
                    timeout,
                    src_addr.ip(),
                    payload,
                    format,
                    time_received_ns,
                    Some(&*metrics),
                    &src_ip,
                    output,
                    enrichment,
                );

                metrics
                    .active_exporters
                    .with_label_values(&["netflow_v9"])
                    .set(v9_parsers.len() as f64);
                metrics
                    .active_exporters
                    .with_label_values(&["ipfix"])
                    .set(ipfix_parsers.len() as f64);
            }
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn parse_netflow(
    v5_parser: &mut NetFlowV5Parser,
    v9_parsers: &mut FxHashMap<IpAddr, NetflowV9Parser>,
    ipfix_parsers: &mut FxHashMap<IpAddr, IpfixParser>,
    sampling_cache: &mut SamplingRateCache,
    ie_registry: &IERegistry,
    timeout: std::time::Duration,
    src: IpAddr,
    payload: &[u8],
    format: OutputFormat,
    time_received_ns: Option<i64>,
    metrics: Option<&metrics::Metrics>,
    src_ip: &str,
    output: &OutputWriter,
    enrichment: &EnrichmentEngine,
) {
    if payload.len() < 2 {
        return;
    }

    let version = u16::from_be_bytes([payload[0], payload[1]]);

    match version {
        NETFLOW_V5_VERSION => match v5_parser.parse(payload) {
            Ok((_, parsed)) => {
                if let Some(m) = metrics {
                    m.flows_processed_total
                        .with_label_values(&["netflow_v5", &src_ip])
                        .inc_by(parsed.flow_records.len() as f64);
                }
                match format {
                    OutputFormat::Raw => output.write_raw(&parsed),
                    OutputFormat::Common => {
                        let ctx = NetFlowV5Context {
                            header: &parsed.header,
                            sampler_address: Some(src),
                        };
                        for record in &parsed.flow_records {
                            let mut common_flow = ctx.convert(record);
                            common_flow.time_received_ns = time_received_ns;
                            let enriched = enrichment.enrich(&common_flow);
                            output.write_enriched_flow(&common_flow, &enriched);
                        }
                    }
                }
            }
            Err(_) => {
                if let Some(m) = metrics {
                    m.parse_errors_total
                        .with_label_values(&["netflow_v5", &src_ip])
                        .inc();
                }
            }
        },
        NETFLOW_V9_VERSION => {
            let parser = v9_parsers
                .entry(src)
                .or_insert_with(|| NetflowV9Parser::new(ie_registry.clone(), timeout));

            match parser.parse(payload) {
                Ok((_, parsed)) => {
                    let flow_count: usize = parsed
                        .flow_sets
                        .iter()
                        .map(|fs| {
                            fs.records
                                .iter()
                                .filter(|r| matches!(r, V9Record::Data(_)))
                                .count()
                        })
                        .sum();

                    if let Some(m) = metrics {
                        m.flows_processed_total
                            .with_label_values(&["netflow_v9", &src_ip])
                            .inc_by(flow_count as f64);
                    }
                    match format {
                        OutputFormat::Raw => output.write_raw(&parsed),
                        OutputFormat::Common => {
                            let cache_key = (src, parsed.header.source_id);

                            for flow_set in &parsed.flow_sets {
                                for record in &flow_set.records {
                                    if let V9Record::Data(data_record) = record {
                                        if let Some(rate) = extract_v9_sampling_rate(data_record) {
                                            sampling_cache.set(cache_key, rate);
                                        }

                                        let ctx = NetFlowV9Context {
                                            header: &parsed.header,
                                            sampler_address: Some(src),
                                            sampling_rate: sampling_cache.get(&cache_key),
                                        };
                                        let mut common_flow = ctx.convert(data_record);
                                        common_flow.time_received_ns = time_received_ns;
                                        let enriched = enrichment.enrich(&common_flow);
                                        output.write_enriched_flow(&common_flow, &enriched);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if let Some(m) = metrics {
                        m.parse_errors_total
                            .with_label_values(&["netflow_v9", &src_ip])
                            .inc();
                    }
                }
            }
        }
        IPFIX_VERSION => {
            let parser = ipfix_parsers
                .entry(src)
                .or_insert_with(|| IpfixParser::new(ie_registry.clone(), timeout));

            match parser.parse(payload) {
                Ok((_, parsed)) => {
                    let flow_count: usize = parsed
                        .sets
                        .iter()
                        .map(|s| {
                            s.records
                                .iter()
                                .filter(|r| matches!(r, IpfixRecord::Data(_)))
                                .count()
                        })
                        .sum();

                    if let Some(m) = metrics {
                        m.flows_processed_total
                            .with_label_values(&["ipfix", &src_ip])
                            .inc_by(flow_count as f64);
                    }
                    match format {
                        OutputFormat::Raw => output.write_raw(&parsed),
                        OutputFormat::Common => {
                            let cache_key = (src, parsed.header.observation_domain_id);

                            for set in &parsed.sets {
                                for record in &set.records {
                                    if let IpfixRecord::Data(data_record) = record {
                                        if let Some(rate) = extract_ipfix_sampling_rate(data_record)
                                        {
                                            sampling_cache.set(cache_key, rate);
                                        }

                                        let ctx = IpfixContext {
                                            header: &parsed.header,
                                            sampler_address: Some(src),
                                            sampling_rate: sampling_cache.get(&cache_key),
                                        };
                                        let mut common_flow = ctx.convert(data_record);
                                        common_flow.time_received_ns = time_received_ns;
                                        let enriched = enrichment.enrich(&common_flow);
                                        output.write_enriched_flow(&common_flow, &enriched);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if let Some(m) = metrics {
                        m.parse_errors_total
                            .with_label_values(&["ipfix", &src_ip])
                            .inc();
                    }
                }
            }
        }
        _ => {
            if let Some(m) = metrics {
                m.unknown_version_total.with_label_values(&[&src_ip]).inc();
            }
            eprintln!("Unknown NetFlow version: {}", version);
        }
    }
}

fn read_sflow_pcap(
    file_path: &str,
    format: OutputFormat,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let file = std::fs::File::open(file_path).expect("Failed to open pcap file");
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");
    let mut parser = SflowV5Parser::default();

    while let Some(pkt) = reader.next_packet() {
        match pkt {
            Ok(packet) => {
                let time_received_ns = Some(pcap_ts_to_nanos(packet.timestamp));
                if let Ok((src, payload)) = parse_udp_packet(&packet.data) {
                    parse_sflow(
                        &mut parser,
                        &payload,
                        format,
                        time_received_ns,
                        None,
                        &src.to_string(),
                        output,
                        enrichment,
                    );
                }
            }
            Err(err) => {
                eprintln!("{:#?}", err);
                break;
            }
        }
    }
}

fn read_sflow_socket(
    host: &str,
    port: u16,
    format: OutputFormat,
    metrics: &Arc<metrics::Metrics>,
    output: &Arc<OutputWriter>,
    enrichment: &Arc<EnrichmentEngine>,
) {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let socket = UdpSocket::bind(addr).expect("Failed to bind to socket");
    println!("Listening for sFlow data on {}", addr);

    let mut buf = [0u8; 65535];
    let mut parser = SflowV5Parser::default();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let src_ip = src_addr.ip().to_string();

                metrics
                    .packets_received_total
                    .with_label_values(&["sflow", &src_ip])
                    .inc();
                metrics
                    .bytes_received_total
                    .with_label_values(&[&src_ip])
                    .inc_by(len as f64);

                let time_received_ns = Some(Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let payload = &buf[..len];
                parse_sflow(
                    &mut parser,
                    payload,
                    format,
                    time_received_ns,
                    Some(&*metrics),
                    &src_ip,
                    output,
                    enrichment,
                );
            }
            Err(err) => {
                eprintln!("Error receiving data: {:#?}", err);
            }
        }
    }
}

fn parse_sflow(
    parser: &mut SflowV5Parser,
    payload: &[u8],
    format: OutputFormat,
    time_received_ns: Option<i64>,
    metrics: Option<&metrics::Metrics>,
    src_ip: &str,
    output: &OutputWriter,
    enrichment: &EnrichmentEngine,
) {
    if payload.len() < 4 {
        return;
    }

    let version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    if version == SFLOW_V5_VERSION {
        match parser.parse(payload) {
            Ok((_, parsed)) => {
                let flow_count = parsed
                    .samples
                    .iter()
                    .filter(|s| matches!(s, Sample::Flow(_) | Sample::ExpandedFlow(_)))
                    .count();

                if let Some(m) = metrics {
                    m.flows_processed_total
                        .with_label_values(&["sflow_v5", src_ip])
                        .inc_by(flow_count as f64);
                }

                match format {
                    OutputFormat::Raw => output.write_raw(&parsed),
                    OutputFormat::Common => {
                        let ctx = SFlowV5Context { header: &parsed };
                        for sample in &parsed.samples {
                            match sample {
                                Sample::Flow(flow_sample) => {
                                    let mut cf = ctx.convert_flow_sample(flow_sample);
                                    cf.time_received_ns = time_received_ns;
                                    let enriched = enrichment.enrich(&cf);
                                    output.write_enriched_flow(&cf, &enriched);
                                }
                                Sample::ExpandedFlow(expanded_sample) => {
                                    let mut cf = ctx.convert_expanded_flow_sample(expanded_sample);
                                    cf.time_received_ns = time_received_ns;
                                    let enriched = enrichment.enrich(&cf);
                                    output.write_enriched_flow(&cf, &enriched);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(_) => {
                if let Some(m) = metrics {
                    m.parse_errors_total
                        .with_label_values(&["sflow_v5", src_ip])
                        .inc();
                }
            }
        }
    } else {
        if let Some(m) = metrics {
            m.unknown_version_total.with_label_values(&[src_ip]).inc();
        }
        eprintln!("Unknown sFlow version: {}", version);
    }
}

fn main() {
    let cli = Cli::parse();

    let mut ie_registry = IERegistry::new_with_iana_elements();
    if let Some(ref path) = cli.ie_mapping {
        match ie_registry.load_from_csv(path) {
            Ok(count) => println!("Loaded {} custom IE definitions from {}", count, path),
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
                    Ok(count) => println!("Loaded {} prefix entries from {}", count, source),
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
        (FlowType::Netflow, Some(path), _) => {
            read_netflow_pcap(path, cli.format, &ie_registry, timeout, &output, &enrichment_engine)
        }
        (FlowType::Netflow, None, Some(port)) => {
            let metrics = Arc::new(metrics::Metrics::new());
            let _metrics_handle =
                metrics::start_metrics_server(Arc::clone(&metrics), cli.metrics_port);
            read_netflow_socket(
                &cli.host,
                *port,
                cli.format,
                &ie_registry,
                timeout,
                &metrics,
                &output,
                &enrichment_engine,
            )
        }
        (FlowType::Sflow, Some(path), _) => {
            read_sflow_pcap(path, cli.format, &output, &enrichment_engine)
        }
        (FlowType::Sflow, None, Some(port)) => {
            let metrics = Arc::new(metrics::Metrics::new());
            let _metrics_handle =
                metrics::start_metrics_server(Arc::clone(&metrics), cli.metrics_port);
            read_sflow_socket(&cli.host, *port, cli.format, &metrics, &output, &enrichment_engine)
        }
        (_, None, None) => {
            eprintln!("Error: Either --pcap or --port must be specified");
            std::process::exit(1);
        }
    }
}
