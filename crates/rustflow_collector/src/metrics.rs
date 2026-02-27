use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use prometheus::{CounterVec, Encoder, GaugeVec, Opts, Registry, TextEncoder};
use tiny_http::{Response, Server};

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
