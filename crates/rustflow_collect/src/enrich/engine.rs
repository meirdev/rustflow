use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::SystemTime;

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use prefix_trie::PrefixMap;
use prometheus::{Counter, Gauge};
use rustflow_core::common::common_flow::CommonFlow;
use serde_json::Value;

use crate::enrich::config::{EnrichmentConfig, FieldMapping, LookupKey, LookupType};
use crate::metrics::Metrics;

#[derive(Debug, Clone)]
pub struct PrefixData {
    pub fields: HashMap<String, String>,
}

struct PrefixTries {
    ipv4: PrefixMap<Ipv4Net, PrefixData>,
    ipv6: PrefixMap<Ipv6Net, PrefixData>,
    /// Rows that were present in the source but skipped because their prefix
    /// could not be parsed.
    skipped_rows: usize,
}

impl PrefixTries {
    fn new() -> Self {
        Self {
            ipv4: PrefixMap::new(),
            ipv6: PrefixMap::new(),
            skipped_rows: 0,
        }
    }

    fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }
}

#[derive(Clone)]
pub struct PrefixEnrichment {
    config: EnrichmentConfig,
    tries: Arc<RwLock<PrefixTries>>,
    loaded_rows: Gauge,
    last_reload: Gauge,
    reload_failures: Counter,
    skipped_rows: Gauge,
}

impl PrefixEnrichment {
    pub fn new(config: EnrichmentConfig, metrics: &Metrics) -> Self {
        let labels = [config.source_file.display().to_string()];
        Self {
            loaded_rows: metrics.enrichment_loaded_rows.with_label_values(&labels),
            last_reload: metrics
                .enrichment_last_reload_timestamp_seconds
                .with_label_values(&labels),
            reload_failures: metrics
                .enrichment_reload_failures_total
                .with_label_values(&labels),
            skipped_rows: metrics.enrichment_skipped_rows.with_label_values(&labels),
            config,
            tries: Arc::new(RwLock::new(PrefixTries::new())),
        }
    }

    pub fn load(&self) -> Result<usize, EnrichmentError> {
        let new_tries = Self::load_from_file(
            &self.config.source_file,
            &self.config.field_mappings,
            self.config.prefix_column.as_deref(),
        )?;
        let count = new_tries.len();
        let skipped = new_tries.skipped_rows;

        {
            let mut tries = self
                .tries
                .write()
                .map_err(|_| EnrichmentError::LockPoisoned)?;
            *tries = new_tries;
        }
        self.record_successful_load(count, skipped);

        Ok(count)
    }

    fn record_successful_load(&self, count: usize, skipped: usize) {
        self.loaded_rows.set(count as f64);
        self.skipped_rows.set(skipped as f64);
        self.last_reload.set(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        );
    }

    fn load_from_file(
        path: &Path,
        field_mappings: &[FieldMapping],
        prefix_column: Option<&str>,
    ) -> Result<PrefixTries, EnrichmentError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("mmdb") => Self::load_from_mmdb(path, field_mappings),
            Some("csv") => {
                let column = prefix_column.ok_or(EnrichmentError::MissingPrefix)?;
                Self::load_from_csv(path, column)
            }
            Some(ext) => Err(EnrichmentError::UnsupportedFormat(ext.to_string())),
            None => Err(EnrichmentError::UnsupportedFormat(
                "no extension".to_string(),
            )),
        }
    }

    fn load_from_csv(path: &Path, prefix_column: &str) -> Result<PrefixTries, EnrichmentError> {
        let mut reader = csv::Reader::from_path(path)?;
        let headers: Vec<String> = reader
            .headers()?
            .iter()
            .map(|s| s.trim().to_string())
            .collect();

        let prefix_col_idx = headers
            .iter()
            .position(|h| h == prefix_column)
            .ok_or_else(|| EnrichmentError::PrefixColumnNotFound {
                column: prefix_column.to_string(),
                headers: headers.clone(),
            })?;

        let mut tries = PrefixTries::new();

        for result in reader.records() {
            let record = result?;
            let prefix_str = record
                .get(prefix_col_idx)
                .ok_or(EnrichmentError::MissingPrefix)?
                .trim();

            if prefix_str.is_empty() {
                continue;
            }

            let mut fields = HashMap::new();
            for (idx, header) in headers.iter().enumerate() {
                if let Some(value) = record.get(idx) {
                    let value = value.trim();
                    if !value.is_empty() {
                        fields.insert(header.clone(), value.to_string());
                    }
                }
            }

            let data = PrefixData { fields };

            if let Ok(ipv4_net) = prefix_str.parse::<Ipv4Net>() {
                tries.ipv4.insert(ipv4_net, data);
            } else if let Ok(ipv6_net) = prefix_str.parse::<Ipv6Net>() {
                tries.ipv6.insert(ipv6_net, data);
            } else {
                eprintln!("Warning: Could not parse prefix: {}", prefix_str);
                tries.skipped_rows += 1;
            }
        }

        Ok(tries)
    }

    fn load_from_mmdb(
        path: &Path,
        field_mappings: &[FieldMapping],
    ) -> Result<PrefixTries, EnrichmentError> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        let mut tries = PrefixTries::new();

        let mut columns: Vec<&str> = field_mappings
            .iter()
            .map(|m| m.source_column.as_str())
            .collect();
        columns.sort_unstable();
        columns.dedup();
        let paths: Vec<(&str, Vec<PathElement<'_>>)> = columns
            .into_iter()
            .map(|column| (column, column.split('.').map(PathElement::Key).collect()))
            .collect();

        for result in reader.networks(Default::default())? {
            let lookup = result?;
            if !lookup.has_data() {
                continue;
            }

            let mut fields = HashMap::new();
            for (column, path) in &paths {
                let value = lookup
                    .decode_path::<serde_json::Value>(path)
                    .ok()
                    .flatten()
                    .and_then(mmdb_value_to_string);
                if let Some(value) = value {
                    fields.insert((*column).to_string(), value);
                }
            }

            if fields.is_empty() {
                continue;
            }

            let data = PrefixData { fields };
            let network = lookup.network()?;

            match network {
                ipnetwork::IpNetwork::V4(v4) => {
                    let net = Ipv4Net::new(v4.ip(), v4.prefix()).map_err(|e| {
                        EnrichmentError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                    tries.ipv4.insert(net, data);
                }
                ipnetwork::IpNetwork::V6(v6) => {
                    let net = Ipv6Net::new(v6.ip(), v6.prefix()).map_err(|e| {
                        EnrichmentError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                    tries.ipv6.insert(net, data);
                }
            }
        }

        Ok(tries)
    }

    fn lookup(&self, addr: &IpAddr) -> Option<PrefixData> {
        let tries = self.tries.read().ok()?;

        match addr {
            IpAddr::V4(v4) => {
                let host_prefix = Ipv4Net::new(*v4, 32).ok()?;
                tries
                    .ipv4
                    .get_lpm(&host_prefix)
                    .map(|(_, data)| data.clone())
            }
            IpAddr::V6(v6) => {
                let host_prefix = Ipv6Net::new(*v6, 128).ok()?;
                tries
                    .ipv6
                    .get_lpm(&host_prefix)
                    .map(|(_, data)| data.clone())
            }
        }
    }

    pub fn enrich(&self, flow: &CommonFlow) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let mut lookups: [Option<Option<PrefixData>>; LookupKey::COUNT] = Default::default();

        for mapping in &self.config.field_mappings {
            let data = lookups[mapping.key.index()].get_or_insert_with(|| {
                mapping
                    .key
                    .extract(flow)
                    .and_then(|addr| self.lookup(&addr))
            });
            let value = data
                .as_ref()
                .and_then(|data| data.fields.get(&mapping.source_column));
            if let Some(value) = value {
                result.insert(mapping.output_field.clone(), value.clone());
            }
        }

        result
    }

    pub fn start_reload_task(&self) {
        if let Some(interval) = self.config.reload_interval {
            let enrichment = self.clone();
            thread::spawn(move || {
                loop {
                    thread::sleep(interval);
                    enrichment.reload();
                }
            });
        }
    }

    fn reload(&self) {
        let path = self.config.source_file.display();
        match self.load() {
            Ok(count) => eprintln!("Reloaded {} prefix entries from {}", count, path),
            Err(e) => {
                self.reload_failures.inc();
                eprintln!("Failed to reload enrichment from {}: {}", path, e);
            }
        }
    }
}

fn mmdb_value_to_string(value: serde_json::Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(_) | Value::Object(_) => Some(value.to_string()),
    }
}

pub struct EnrichmentEngine {
    prefix_enrichments: Vec<PrefixEnrichment>,
    output_fields: Vec<String>,
    metrics: Arc<Metrics>,
}

impl EnrichmentEngine {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            prefix_enrichments: Vec::new(),
            output_fields: Vec::new(),
            metrics,
        }
    }

    pub fn add(&mut self, config: EnrichmentConfig) -> Result<usize, EnrichmentError> {
        for mapping in &config.field_mappings {
            if !self.output_fields.contains(&mapping.output_field) {
                self.output_fields.push(mapping.output_field.clone());
            }
        }

        match config.lookup_type {
            LookupType::PrefixLookup => {
                let enrichment = PrefixEnrichment::new(config, &self.metrics);
                let count = enrichment.load()?;
                enrichment.start_reload_task();
                self.prefix_enrichments.push(enrichment);
                Ok(count)
            }
        }
    }

    pub fn output_fields(&self) -> &[String] {
        &self.output_fields
    }

    pub fn enrich(&self, flow: &CommonFlow) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for enrichment in &self.prefix_enrichments {
            result.extend(enrichment.enrich(flow));
        }
        result
    }
}

#[derive(Debug)]
pub enum EnrichmentError {
    Csv(csv::Error),
    Io(std::io::Error),
    MaxmindDb(maxminddb::MaxMindDbError),
    UnsupportedFormat(String),
    PrefixColumnNotFound {
        column: String,
        headers: Vec<String>,
    },
    MissingPrefix,
    LockPoisoned,
}

impl std::fmt::Display for EnrichmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv(e) => write!(f, "CSV error: {}", e),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::MaxmindDb(e) => write!(f, "MaxMind DB error: {}", e),
            Self::UnsupportedFormat(ext) => {
                write!(
                    f,
                    "Unsupported file format: '{}'. Supported: csv, mmdb",
                    ext
                )
            }
            Self::PrefixColumnNotFound { column, headers } => write!(
                f,
                "Prefix column '{}' not found in CSV header; available columns: {}",
                column,
                headers.join(", ")
            ),
            Self::MissingPrefix => write!(f, "CSV sources require 'prefix_column'"),
            Self::LockPoisoned => write!(f, "Lock poisoned"),
        }
    }
}

impl std::error::Error for EnrichmentError {}

impl From<csv::Error> for EnrichmentError {
    fn from(e: csv::Error) -> Self {
        Self::Csv(e)
    }
}

impl From<std::io::Error> for EnrichmentError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<maxminddb::MaxMindDbError> for EnrichmentError {
    fn from(e: maxminddb::MaxMindDbError) -> Self {
        Self::MaxmindDb(e)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Ipv4Addr;

    use rustflow_core::common::common_flow::FlowType;

    use super::*;

    fn csv_file(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn prefix_column_is_found_by_name() {
        // the prefix column need not be first, nor have any particular name
        let path = csv_file(
            "rustflow_enrich_custom_col.csv",
            "prefix,subnet,asn\nignored,10.0.0.0/8,64500\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path, "subnet").unwrap();
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert_eq!(data.fields.get("asn").map(String::as_str), Some("64500"));
        assert_eq!(
            data.fields.get("subnet").map(String::as_str),
            Some("10.0.0.0/8")
        );

        let Err(err) = PrefixEnrichment::load_from_csv(&path, "nope") else {
            panic!("unknown prefix column was accepted");
        };
        assert!(
            matches!(err, EnrichmentError::PrefixColumnNotFound { .. }),
            "{}",
            err
        );
        assert!(err.to_string().contains("prefix, subnet, asn"), "{}", err);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn each_key_is_looked_up_independently() {
        let path = csv_file(
            "rustflow_enrich_multi_key.csv",
            "prefix,asn\n10.0.0.0/8,64500\n192.168.0.0/16,64501\n",
        );
        let mapping = |key, src: &str, dst: &str| FieldMapping {
            key,
            source_column: src.to_string(),
            output_field: dst.to_string(),
        };
        let enrichment = PrefixEnrichment::new(
            EnrichmentConfig {
                lookup_type: LookupType::PrefixLookup,
                source_file: path.clone(),
                field_mappings: vec![
                    mapping(LookupKey::SrcAddr, "asn", "src_asn"),
                    mapping(LookupKey::SrcAddr, "prefix", "src_net"),
                    mapping(LookupKey::DstAddr, "asn", "dst_asn"),
                    mapping(LookupKey::NextHop, "asn", "next_hop_asn"),
                ],
                prefix_column: Some("prefix".to_string()),
                reload_interval: None,
            },
            &Metrics::new(),
        );
        assert_eq!(enrichment.load().unwrap(), 2);

        let mut flow = CommonFlow::new(FlowType::Ipfix);
        flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)));
        flow.dst_addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        // next_hop stays None

        let out = enrichment.enrich(&flow);
        assert_eq!(out.get("src_asn").map(String::as_str), Some("64500"));
        assert_eq!(out.get("src_net").map(String::as_str), Some("10.0.0.0/8"));
        assert_eq!(out.get("dst_asn").map(String::as_str), Some("64501"));
        assert!(!out.contains_key("next_hop_asn"));
        assert_eq!(out.len(), 3);

        std::fs::remove_file(&path).ok();
    }

    fn csv_config(path: &std::path::Path, key: LookupKey, out: &str) -> EnrichmentConfig {
        EnrichmentConfig {
            lookup_type: LookupType::PrefixLookup,
            source_file: path.to_path_buf(),
            field_mappings: vec![FieldMapping {
                key,
                source_column: "asn".to_string(),
                output_field: out.to_string(),
            }],
            prefix_column: Some("prefix".to_string()),
            reload_interval: None,
        }
    }

    #[test]
    fn successful_load_records_metrics() {
        let path = csv_file(
            "rustflow_enrich_metrics.csv",
            "prefix,asn\n10.0.0.0/8,64512\n",
        );
        let source = path.display().to_string();
        let metrics = Arc::new(Metrics::new());
        let mut engine = EnrichmentEngine::new(Arc::clone(&metrics));
        let count = engine
            .add(csv_config(&path, LookupKey::DstAddr, "dst_asn"))
            .unwrap();

        assert_eq!(count, 1);
        let labels = [source.as_str()];
        assert_eq!(
            metrics
                .enrichment_loaded_rows
                .with_label_values(&labels)
                .get(),
            1.0
        );
        assert_eq!(
            metrics
                .enrichment_skipped_rows
                .with_label_values(&labels)
                .get(),
            0.0
        );
        assert!(
            metrics
                .enrichment_last_reload_timestamp_seconds
                .with_label_values(&labels)
                .get()
                > 0.0
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn failed_reload_counts_a_failure_and_keeps_previous_data() {
        let path = csv_file(
            "rustflow_enrich_reload_failure.csv",
            "prefix,asn\n10.0.0.0/8,64512\n",
        );
        let source = path.display().to_string();
        let metrics = Arc::new(Metrics::new());
        let enrichment =
            PrefixEnrichment::new(csv_config(&path, LookupKey::SrcAddr, "src_asn"), &metrics);
        assert_eq!(enrichment.load().unwrap(), 1);

        // the prefix column disappears, so the reload fails
        std::fs::write(&path, "garbage,asn\nfoo,bar\n").unwrap();
        enrichment.reload();

        let labels = [source.as_str()];
        assert_eq!(
            metrics
                .enrichment_reload_failures_total
                .with_label_values(&labels)
                .get(),
            1.0
        );
        assert_eq!(
            metrics
                .enrichment_loaded_rows
                .with_label_values(&labels)
                .get(),
            1.0
        );
        let data = enrichment
            .lookup(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
            .expect("previous data should still be served");
        assert_eq!(data.fields.get("asn").map(String::as_str), Some("64512"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn unparsable_rows_are_counted_as_skipped() {
        let path = csv_file(
            "rustflow_enrich_skipped.csv",
            "prefix,asn\n10.0.0.0/8,1\nnot-a-prefix,2\n10.1.0.0/16,3\n",
        );
        let source = path.display().to_string();
        let metrics = Arc::new(Metrics::new());
        let mut engine = EnrichmentEngine::new(Arc::clone(&metrics));
        let count = engine
            .add(csv_config(&path, LookupKey::DstAddr, "dst_asn"))
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            metrics
                .enrichment_skipped_rows
                .with_label_values(&[source.as_str()])
                .get(),
            1.0
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn prefix_column_is_available_as_a_field() {
        let path = csv_file(
            "rustflow_enrich_prefix.csv",
            "prefix,asn,org\n\
             10.0.0.0/8,13335,CLOUDFLARENET\n\
             10.1.0.0/16,2519,VECTANT\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path, "prefix").unwrap();

        // longest-prefix match wins, and reports its own network
        let net = Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert_eq!(
            data.fields.get("prefix").map(String::as_str),
            Some("10.1.0.0/16")
        );
        assert_eq!(data.fields.get("asn").map(String::as_str), Some("2519"));

        let net = Ipv4Net::new(Ipv4Addr::new(10, 9, 9, 9), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert_eq!(
            data.fields.get("prefix").map(String::as_str),
            Some("10.0.0.0/8")
        );
        assert_eq!(
            data.fields.get("org").map(String::as_str),
            Some("CLOUDFLARENET")
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn csv_without_prefix_column_is_rejected() {
        let path = csv_file("rustflow_enrich_no_col.csv", "prefix,asn\n10.0.0.0/8,192\n");
        let Err(err) = PrefixEnrichment::load_from_file(&path, &[], None) else {
            panic!("CSV without prefix_column was accepted");
        };
        assert!(matches!(err, EnrichmentError::MissingPrefix), "{}", err);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_values_are_omitted_rather_than_stored_blank() {
        let path = csv_file(
            "rustflow_enrich_empty.csv",
            "prefix,asn,org\n10.0.0.0/8,,ACME\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path, "prefix").unwrap();
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert!(!data.fields.contains_key("asn"));
        assert_eq!(data.fields.get("org").map(String::as_str), Some("ACME"));
        std::fs::remove_file(&path).ok();
    }
}
