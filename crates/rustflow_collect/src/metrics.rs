use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread;

use prometheus_client::encoding::{EncodeLabelSet, text};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use rustc_hash::FxHashMap;
use tiny_http::{Response, Server};

use crate::enrich::TableMetrics;
use crate::sink::OutputMetrics;

// Metric label constants
pub const LABEL_NETFLOW: &str = "netflow";
pub const LABEL_NETFLOW_V5: &str = "netflow_v5";
pub const LABEL_NETFLOW_V9: &str = "netflow_v9";
pub const LABEL_IPFIX: &str = "ipfix";
pub const LABEL_SFLOW: &str = "sflow";
pub const LABEL_SFLOW_V5: &str = "sflow_v5";

/// Content type of the OpenMetrics text format the registry is encoded in.
const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TypeLabel {
    pub r#type: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SourceLabel {
    pub source_ip: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TypeSourceLabel {
    pub r#type: &'static str,
    pub source_ip: String,
}

pub struct Metrics {
    pub registry: Registry,

    /// Total UDP packets received, labeled by type, source_ip
    pub packets_received_total: Family<TypeSourceLabel, Counter>,

    /// Total bytes received, labeled by source_ip
    pub bytes_received_total: Family<SourceLabel, Counter>,

    /// Total flows successfully parsed, labeled by type, source_ip
    pub flows_processed_total: Family<TypeSourceLabel, Counter>,

    /// Total parse errors, labeled by type, source_ip
    pub parse_errors_total: Family<TypeSourceLabel, Counter>,

    /// Unknown protocol versions encountered, labeled by source_ip
    pub unknown_version_total: Family<SourceLabel, Counter>,

    /// Number of unique exporters (netflow_v9/ipfix)
    pub active_exporters: Family<TypeLabel, Gauge>,

    /// Load statistics of the enrichment tables, labeled by source
    pub enrichment: TableMetrics,

    /// Flows, bytes and files written by the output sink, and its failures
    pub output: OutputMetrics,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Counters are registered without `_total`; the encoder appends it.
        let packets_received_total = Family::default();
        registry.register(
            "packets_received",
            "Total UDP packets received",
            packets_received_total.clone(),
        );

        let bytes_received_total = Family::default();
        registry.register(
            "bytes_received",
            "Total bytes received",
            bytes_received_total.clone(),
        );

        let flows_processed_total = Family::default();
        registry.register(
            "flows_processed",
            "Total flows successfully parsed",
            flows_processed_total.clone(),
        );

        let parse_errors_total = Family::default();
        registry.register(
            "parse_errors",
            "Total parse errors",
            parse_errors_total.clone(),
        );

        let unknown_version_total = Family::default();
        registry.register(
            "unknown_version",
            "Unknown protocol versions encountered",
            unknown_version_total.clone(),
        );

        let active_exporters = Family::default();
        registry.register(
            "active_exporters",
            "Number of unique exporters",
            active_exporters.clone(),
        );

        let enrichment = TableMetrics::new();
        enrichment.register(&mut registry);

        let output = OutputMetrics::new();
        output.register(&mut registry);

        Metrics {
            registry,
            enrichment,
            output,
            packets_received_total,
            bytes_received_total,
            flows_processed_total,
            parse_errors_total,
            unknown_version_total,
            active_exporters,
        }
    }

    pub fn active_exporters(&self, version: &'static str) -> Gauge {
        self.active_exporters
            .get_or_create_owned(&TypeLabel { r#type: version })
    }

    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        text::encode(&mut buffer, &self.registry).unwrap();
        buffer
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

struct ExporterCounters {
    packets_received: Counter,
    bytes_received: Counter,
    flows_processed: Counter,
    parse_errors: Counter,
}

pub struct ExporterMetrics {
    metrics: Arc<Metrics>,
    family: &'static str,
    counters: FxHashMap<(IpAddr, &'static str), ExporterCounters>,
}

impl ExporterMetrics {
    pub fn new(metrics: Arc<Metrics>, family: &'static str) -> Self {
        Self {
            metrics,
            family,
            counters: FxHashMap::default(),
        }
    }

    fn get_or_create(&mut self, src: IpAddr, version: &'static str) -> &ExporterCounters {
        let (metrics, family) = (&self.metrics, self.family);
        self.counters.entry((src, version)).or_insert_with(|| {
            let source_ip = src.to_string();
            let by_source = SourceLabel {
                source_ip: source_ip.clone(),
            };
            let by_family = TypeSourceLabel {
                r#type: family,
                source_ip: source_ip.clone(),
            };
            let by_version = TypeSourceLabel {
                r#type: version,
                source_ip,
            };
            ExporterCounters {
                packets_received: metrics
                    .packets_received_total
                    .get_or_create_owned(&by_family),
                bytes_received: metrics.bytes_received_total.get_or_create_owned(&by_source),
                flows_processed: metrics
                    .flows_processed_total
                    .get_or_create_owned(&by_version),
                parse_errors: metrics.parse_errors_total.get_or_create_owned(&by_version),
            }
        })
    }

    pub fn record_packet(
        &mut self,
        src: IpAddr,
        version: &'static str,
        bytes: usize,
        flow_count: usize,
    ) {
        let counters = self.get_or_create(src, version);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as u64);
        counters.flows_processed.inc_by(flow_count as u64);
    }

    pub fn record_parse_error(&mut self, src: IpAddr, version: &'static str, bytes: usize) {
        let counters = self.get_or_create(src, version);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as u64);
        counters.parse_errors.inc();
    }

    pub fn record_unknown_version(&mut self, src: IpAddr, bytes: usize) {
        let source_ip = src.to_string();
        self.metrics
            .packets_received_total
            .get_or_create(&TypeSourceLabel {
                r#type: self.family,
                source_ip: source_ip.clone(),
            })
            .inc();
        self.metrics
            .bytes_received_total
            .get_or_create(&SourceLabel {
                source_ip: source_ip.clone(),
            })
            .inc_by(bytes as u64);
        self.metrics
            .unknown_version_total
            .get_or_create(&SourceLabel { source_ip })
            .inc();
    }
}

pub fn start_metrics_server(
    metrics: Arc<Metrics>,
    host: &str,
    port: u16,
) -> thread::JoinHandle<()> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

    thread::spawn(move || {
        let server = Server::http(addr).expect("Failed to start metrics HTTP server");
        eprintln!("Metrics server listening on http://{}/metrics", addr);

        for request in server.incoming_requests() {
            let response = if request.url() == "/metrics" {
                let body = metrics.encode();
                Response::from_string(body).with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], CONTENT_TYPE.as_bytes())
                        .unwrap(),
                )
            } else {
                Response::from_string("Not Found").with_status_code(404)
            };

            let _ = request.respond(response);
        }
    })
}
