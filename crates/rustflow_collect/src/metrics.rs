use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread;

use prometheus::{Counter, CounterVec, Encoder, GaugeVec, Opts, Registry, TextEncoder};
use rustc_hash::FxHashMap;
use tiny_http::{Response, Server};

// Metric label constants
pub const LABEL_NETFLOW: &str = "netflow";
pub const LABEL_NETFLOW_V5: &str = "netflow_v5";
pub const LABEL_NETFLOW_V9: &str = "netflow_v9";
pub const LABEL_IPFIX: &str = "ipfix";
pub const LABEL_SFLOW: &str = "sflow";
pub const LABEL_SFLOW_V5: &str = "sflow_v5";

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,

    /// Total UDP packets received, labeled by type, source_ip
    pub packets_received_total: CounterVec,

    /// Total bytes received, labeled by source_ip
    pub bytes_received_total: CounterVec,

    /// Total flows successfully parsed, labeled by type, source_ip
    pub flows_processed_total: CounterVec,

    /// Total parse errors, labeled by type, source_ip
    pub parse_errors_total: CounterVec,

    /// Unknown protocol versions encountered, labeled by source_ip
    pub unknown_version_total: CounterVec,

    /// Number of unique exporters (netflow_v9/ipfix)
    pub active_exporters: GaugeVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let packets_received_total = CounterVec::new(
            Opts::new("packets_received_total", "Total UDP packets received"),
            &["type", "source_ip"],
        )
        .unwrap();

        let bytes_received_total = CounterVec::new(
            Opts::new("bytes_received_total", "Total bytes received"),
            &["source_ip"],
        )
        .unwrap();

        let flows_processed_total = CounterVec::new(
            Opts::new("flows_processed_total", "Total flows successfully parsed"),
            &["type", "source_ip"],
        )
        .unwrap();

        let parse_errors_total = CounterVec::new(
            Opts::new("parse_errors_total", "Total parse errors"),
            &["type", "source_ip"],
        )
        .unwrap();

        let unknown_version_total = CounterVec::new(
            Opts::new(
                "unknown_version_total",
                "Unknown protocol versions encountered",
            ),
            &["source_ip"],
        )
        .unwrap();

        let active_exporters = GaugeVec::new(
            Opts::new("active_exporters", "Number of unique exporters"),
            &["type"],
        )
        .unwrap();

        registry
            .register(Box::new(packets_received_total.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_received_total.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_processed_total.clone()))
            .unwrap();
        registry
            .register(Box::new(parse_errors_total.clone()))
            .unwrap();
        registry
            .register(Box::new(unknown_version_total.clone()))
            .unwrap();
        registry
            .register(Box::new(active_exporters.clone()))
            .unwrap();

        Metrics {
            registry,
            packets_received_total,
            bytes_received_total,
            flows_processed_total,
            parse_errors_total,
            unknown_version_total,
            active_exporters,
        }
    }

    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Cached counters for a single exporter IP to avoid string allocations.
struct ExporterCounters {
    packets_received: Counter,
    bytes_received: Counter,
    flows_processed: Counter,
    parse_errors: Counter,
}

/// Cached metrics for NetFlow exporters.
/// Avoids string allocation on every packet by caching Counter objects per IP.
pub struct NetflowMetricsCache {
    metrics: Arc<Metrics>,
    /// Cached counters per (src_ip, version_label)
    v5_cache: FxHashMap<IpAddr, ExporterCounters>,
    v9_cache: FxHashMap<IpAddr, ExporterCounters>,
    ipfix_cache: FxHashMap<IpAddr, ExporterCounters>,
}

impl NetflowMetricsCache {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            v5_cache: FxHashMap::default(),
            v9_cache: FxHashMap::default(),
            ipfix_cache: FxHashMap::default(),
        }
    }

    fn get_or_create(&mut self, src: IpAddr, version_label: &'static str) -> &ExporterCounters {
        let cache = match version_label {
            LABEL_NETFLOW_V5 => &mut self.v5_cache,
            LABEL_NETFLOW_V9 => &mut self.v9_cache,
            LABEL_IPFIX => &mut self.ipfix_cache,
            _ => &mut self.v5_cache, // fallback
        };

        cache.entry(src).or_insert_with(|| {
            let src_str = src.to_string();
            ExporterCounters {
                packets_received: self
                    .metrics
                    .packets_received_total
                    .with_label_values(&[LABEL_NETFLOW, &src_str]),
                bytes_received: self
                    .metrics
                    .bytes_received_total
                    .with_label_values(&[&src_str]),
                flows_processed: self
                    .metrics
                    .flows_processed_total
                    .with_label_values(&[version_label, &src_str]),
                parse_errors: self
                    .metrics
                    .parse_errors_total
                    .with_label_values(&[version_label, &src_str]),
            }
        })
    }

    /// Record a successful packet with flows.
    pub fn record_packet(
        &mut self,
        src: IpAddr,
        version_label: &'static str,
        bytes: usize,
        flow_count: usize,
    ) {
        let counters = self.get_or_create(src, version_label);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as f64);
        counters.flows_processed.inc_by(flow_count as f64);
    }

    /// Record a parse error.
    pub fn record_parse_error(&mut self, src: IpAddr, version_label: &'static str, bytes: usize) {
        let counters = self.get_or_create(src, version_label);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as f64);
        counters.parse_errors.inc();
    }

    /// Record an unknown version error.
    pub fn record_unknown_version(&mut self, src: IpAddr, bytes: usize) {
        // For unknown versions, we still need to allocate for the source IP
        // but this is rare (only happens for truly unknown protocols)
        let src_str = src.to_string();
        self.metrics
            .packets_received_total
            .with_label_values(&[LABEL_NETFLOW, &src_str])
            .inc();
        self.metrics
            .bytes_received_total
            .with_label_values(&[&src_str])
            .inc_by(bytes as f64);
        self.metrics
            .unknown_version_total
            .with_label_values(&[&src_str])
            .inc();
    }

    /// Get reference to underlying metrics for exporter counts.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

/// Cached metrics for sFlow exporters.
pub struct SflowMetricsCache {
    metrics: Arc<Metrics>,
    cache: FxHashMap<IpAddr, ExporterCounters>,
}

impl SflowMetricsCache {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            cache: FxHashMap::default(),
        }
    }

    fn get_or_create(&mut self, src: IpAddr) -> &ExporterCounters {
        self.cache.entry(src).or_insert_with(|| {
            let src_str = src.to_string();
            ExporterCounters {
                packets_received: self
                    .metrics
                    .packets_received_total
                    .with_label_values(&[LABEL_SFLOW, &src_str]),
                bytes_received: self
                    .metrics
                    .bytes_received_total
                    .with_label_values(&[&src_str]),
                flows_processed: self
                    .metrics
                    .flows_processed_total
                    .with_label_values(&[LABEL_SFLOW_V5, &src_str]),
                parse_errors: self
                    .metrics
                    .parse_errors_total
                    .with_label_values(&[LABEL_SFLOW_V5, &src_str]),
            }
        })
    }

    /// Record a successful packet with flows.
    pub fn record_packet(&mut self, src: IpAddr, bytes: usize, flow_count: usize) {
        let counters = self.get_or_create(src);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as f64);
        counters.flows_processed.inc_by(flow_count as f64);
    }

    /// Record a parse error.
    pub fn record_parse_error(&mut self, src: IpAddr, bytes: usize) {
        let counters = self.get_or_create(src);
        counters.packets_received.inc();
        counters.bytes_received.inc_by(bytes as f64);
        counters.parse_errors.inc();
    }

    /// Record an unknown version error.
    pub fn record_unknown_version(&mut self, src: IpAddr, bytes: usize) {
        let src_str = src.to_string();
        self.metrics
            .packets_received_total
            .with_label_values(&[LABEL_SFLOW, &src_str])
            .inc();
        self.metrics
            .bytes_received_total
            .with_label_values(&[&src_str])
            .inc_by(bytes as f64);
        self.metrics
            .unknown_version_total
            .with_label_values(&[&src_str])
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
                    tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"text/plain; version=0.0.4; charset=utf-8"[..],
                    )
                    .unwrap(),
                )
            } else {
                Response::from_string("Not Found").with_status_code(404)
            };

            let _ = request.respond(response);
        }
    })
}
