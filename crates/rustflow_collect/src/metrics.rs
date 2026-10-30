use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, thread};

use log::info;
use prometheus_client::encoding::{EncodeLabelSet, text};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use rustc_hash::FxHashMap;
use tiny_http::{Response, Server};

use crate::enrich::TableMetrics;
use crate::sink::OutputMetrics;

const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SourceLabel {
    pub source_ip: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TypeSourceLabel {
    pub r#type: &'static str,
    pub source_ip: String,
}

/// What the ingest threads count per exporter.
#[derive(Clone, Default)]
pub struct InputMetrics {
    /// Datagrams received, by protocol family and source.
    pub packets_received: Family<TypeSourceLabel, Counter>,
    /// Bytes received, by source.
    pub bytes_received: Family<SourceLabel, Counter>,
    /// Flows successfully parsed, by protocol version and source.
    pub flows_processed: Family<TypeSourceLabel, Counter>,
    /// Parse errors, by protocol version and source.
    pub parse_errors: Family<TypeSourceLabel, Counter>,
    /// Datagrams of an unknown protocol version, by source.
    pub unknown_version: Family<SourceLabel, Counter>,
    /// Unix time of the last datagram, by protocol family and source.
    pub exporter_last_seen: Family<TypeSourceLabel, Gauge>,
}

impl InputMetrics {
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "packets_received",
            "Total UDP packets received",
            self.packets_received.clone(),
        );
        registry.register(
            "bytes_received",
            "Total bytes received",
            self.bytes_received.clone(),
        );
        registry.register(
            "flows_processed",
            "Total flows successfully parsed",
            self.flows_processed.clone(),
        );
        registry.register(
            "parse_errors",
            "Total parse errors",
            self.parse_errors.clone(),
        );
        registry.register(
            "unknown_version",
            "Unknown protocol versions encountered",
            self.unknown_version.clone(),
        );
        registry.register(
            "exporter_last_seen_timestamp_seconds",
            "Unix time of the last datagram from the exporter",
            self.exporter_last_seen.clone(),
        );
    }
}

pub struct Metrics {
    pub registry: Registry,
    /// Datagrams and flows received, and parse failures, labeled by exporter
    pub input: InputMetrics,
    /// Load statistics of the enrichment tables, labeled by source
    pub enrichment: TableMetrics,
    /// Flows, bytes and files written by the output sink, and its failures
    pub output: OutputMetrics,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let input = InputMetrics::default();
        input.register(&mut registry);

        let enrichment = TableMetrics::new();
        enrichment.register(&mut registry);

        let output = OutputMetrics::new();
        output.register(&mut registry);

        Metrics {
            registry,
            input,
            enrichment,
            output,
        }
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
    last_seen: FxHashMap<IpAddr, Gauge>,
}

impl ExporterMetrics {
    pub fn new(metrics: Arc<Metrics>, family: &'static str) -> Self {
        Self {
            metrics,
            family,
            counters: FxHashMap::default(),
            last_seen: FxHashMap::default(),
        }
    }

    /// Any datagram counts, whether it parses or not. `time_received_ns`
    /// falls back to the current time.
    pub fn heard_from(&mut self, src: IpAddr, time_received_ns: Option<i64>) {
        let (input, family) = (&self.metrics.input, self.family);
        let gauge = self.last_seen.entry(src).or_insert_with(|| {
            input
                .exporter_last_seen
                .get_or_create_owned(&TypeSourceLabel {
                    r#type: family,
                    source_ip: src.to_string(),
                })
        });
        let secs = match time_received_ns {
            Some(ns) => ns.div_euclid(1_000_000_000),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
        };
        gauge.set(secs);
    }

    fn get_or_create(&mut self, src: IpAddr, version: &'static str) -> &ExporterCounters {
        let (input, family) = (&self.metrics.input, self.family);
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
                packets_received: input.packets_received.get_or_create_owned(&by_family),
                bytes_received: input.bytes_received.get_or_create_owned(&by_source),
                flows_processed: input.flows_processed.get_or_create_owned(&by_version),
                parse_errors: input.parse_errors.get_or_create_owned(&by_version),
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
        let input = &self.metrics.input;
        input
            .packets_received
            .get_or_create(&TypeSourceLabel {
                r#type: self.family,
                source_ip: source_ip.clone(),
            })
            .inc();
        input
            .bytes_received
            .get_or_create(&SourceLabel {
                source_ip: source_ip.clone(),
            })
            .inc_by(bytes as u64);
        input
            .unknown_version
            .get_or_create(&SourceLabel { source_ip })
            .inc();
    }
}

/// Binds right away, so a taken port fails at startup.
pub fn start_metrics_server(
    metrics: Arc<Metrics>,
    host: IpAddr,
    port: u16,
) -> io::Result<thread::JoinHandle<()>> {
    let addr = SocketAddr::new(host, port);
    let server = Server::http(addr).map_err(io::Error::other)?;
    info!("Metrics server listening on http://{}/metrics", addr);

    Ok(thread::spawn(move || {
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
    }))
}
