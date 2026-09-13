//! The flow-level engine: each key field is looked up once, every source
//! contributes its mapped fields, and load statistics reach Prometheus.
use std::fs;
use std::path::Path;

use prometheus::{Encoder, Registry, TextEncoder};
use rustflow_collect::enrich::*;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

fn engine(dir: &Path, args: &[String]) -> EnrichmentEngine {
    engine_with(TableMetrics::new(), dir, args)
}

fn engine_with(metrics: TableMetrics, dir: &Path, args: &[String]) -> EnrichmentEngine {
    let mut engine = EnrichmentEngine::new(metrics);
    for arg in args {
        let arg = arg.replace("{dir}", &dir.display().to_string());
        engine.add(parse_enrich_arg(&arg).unwrap()).unwrap();
    }
    engine
}

fn flow() -> CommonFlow {
    let mut flow = CommonFlow::new(FlowType::NetflowV9);
    flow.src_addr = Some("10.1.2.3".parse().unwrap());
    flow.dst_addr = Some("192.0.2.9".parse().unwrap());
    flow.proto = Some(17);
    flow.dst_port = Some(53);
    flow
}

#[test]
fn each_key_is_looked_up_once_and_mapped_to_its_own_fields() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("asn.csv"),
        "prefix,asn,org\n10.0.0.0/8,64500,ten\n192.0.2.0/24,64501,doc\n",
    )
    .unwrap();
    let engine = engine(
        dir.path(),
        &["type=prefix_lookup,source={dir}/asn.csv,key_column=prefix,fields=src_addr@asn:src_asn|prefix:src_net;dst_addr@asn:dst_asn;next_hop@asn:next_hop_asn".into()],
    );
    assert_eq!(
        engine.output_fields(),
        ["src_asn", "src_net", "dst_asn", "next_hop_asn"]
    );
    let out = engine.enrich(&flow());
    assert_eq!(out["src_asn"], "64500");
    assert_eq!(out["src_net"], "10.0.0.0/8");
    assert_eq!(out["dst_asn"], "64501");
    // The flow has no next hop, so that field is absent rather than blank.
    assert_eq!(out.len(), 3);
}

#[test]
fn sources_combine_and_exact_lookups_use_numeric_flow_fields() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("asn.csv"), "prefix,asn\n10.0.0.0/8,64500\n").unwrap();
    fs::write(
        dir.path().join("protocols.csv"),
        "number,name\n6,tcp\n17,udp\n",
    )
    .unwrap();
    fs::write(dir.path().join("ports.csv"), "port,service\n53,dns\n").unwrap();
    let engine = engine(
        dir.path(),
        &[
            "type=prefix_lookup,source={dir}/asn.csv,key_column=prefix,fields=src_addr@asn:src_asn".into(),
            "type=exact,source={dir}/protocols.csv,key_column=number,fields=proto@name:proto_name".into(),
            "type=exact,source={dir}/ports.csv,key_column=port,fields=src_port@service:src_service;dst_port@service:dst_service".into(),
        ],
    );
    let out = engine.enrich(&flow());
    assert_eq!(out["src_asn"], "64500");
    assert_eq!(out["proto_name"], "udp");
    assert_eq!(out["dst_service"], "dns");
    assert!(!out.contains_key("src_service"));
    assert_eq!(out.len(), 3);
}

#[test]
fn mmdb_source_enriches_with_nested_paths() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.mmdb");
    let engine = engine(
        Path::new("."),
        &[format!(
            "type=prefix_lookup,source={},fields=src_addr@country.iso_code:src_country|asn:src_asn",
            fixture.display()
        )],
    );
    let out = engine.enrich(&flow());
    assert_eq!(out["src_country"], "ZY");
    assert_eq!(out["src_asn"], "64512");
}

#[test]
fn load_statistics_are_exposed_as_prometheus_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("asn.csv");
    fs::write(&path, "prefix,asn\n10.0.0.0/8,64500\n").unwrap();
    let metrics = TableMetrics::new();
    let registry = Registry::new();
    metrics.register(&registry).unwrap();
    let _engine = engine_with(
        metrics,
        dir.path(),
        &[
            "type=prefix_lookup,source={dir}/asn.csv,key_column=prefix,fields=src_addr@asn:src_asn"
                .into(),
        ],
    );
    let mut buffer = Vec::new();
    TextEncoder::new()
        .encode(&registry.gather(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // Labeled by the absolute source path, as the configuration stores it.
    let source = std::path::absolute(&path).unwrap().display().to_string();
    assert!(
        text.contains(&format!("enrichment_loaded_rows{{source=\"{source}\"}} 1")),
        "{text}"
    );
    assert!(
        text.contains(&format!("enrichment_loads_total{{source=\"{source}\"}} 1")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "enrichment_reload_failures_total{{source=\"{source}\"}} 0"
        )),
        "{text}"
    );
}
