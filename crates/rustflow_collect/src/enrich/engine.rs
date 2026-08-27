use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use std::{fs, thread};

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use notify_debouncer_full::notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use prefix_trie::PrefixMap;
use prometheus::{Counter, Gauge};
use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, FieldMapping, LookupType, ReloadMode};
use crate::metrics::Metrics;

/// Column names that are recognized as prefix/network columns in CSV files
const PREFIX_COLUMN_NAMES: &[&str] = &["prefix", "network", "cidr"];

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
        let labels = [
            config.source_file.display().to_string(),
            config.lookup_key.as_str().to_string(),
        ];
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
        let new_tries =
            Self::load_from_file(&self.config.source_file, &self.config.field_mappings)?;
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
    ) -> Result<PrefixTries, EnrichmentError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("mmdb") => Self::load_from_mmdb(path, field_mappings),
            Some("csv") => Self::load_from_csv(path),
            Some(ext) => Err(EnrichmentError::UnsupportedFormat(ext.to_string())),
            None => Err(EnrichmentError::UnsupportedFormat(
                "no extension".to_string(),
            )),
        }
    }

    fn load_from_csv(path: &Path) -> Result<PrefixTries, EnrichmentError> {
        let mut reader = csv::Reader::from_path(path)?;
        let headers: Vec<String> = reader.headers()?.iter().map(|s| s.to_string()).collect();

        let prefix_col_idx = headers
            .iter()
            .position(|h| {
                let h_lower = h.to_lowercase();
                PREFIX_COLUMN_NAMES.contains(&h_lower.as_str())
            })
            .ok_or(EnrichmentError::MissingPrefix)?;

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

        let paths: Vec<(&FieldMapping, Vec<PathElement<'_>>)> = field_mappings
            .iter()
            .map(|m| {
                let path = m.source_column.split('.').map(PathElement::Key).collect();
                (m, path)
            })
            .collect();

        for result in reader.networks(Default::default())? {
            let lookup = result?;
            if !lookup.has_data() {
                continue;
            }

            let mut fields = HashMap::new();
            for (mapping, path) in &paths {
                if let Ok(Some(value)) = lookup.decode_path::<String>(path) {
                    if !value.is_empty() {
                        fields.insert(mapping.source_column.clone(), value);
                    }
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

        if let Some(addr) = self.config.lookup_key.extract(flow) {
            if let Some(data) = self.lookup(&addr) {
                for mapping in &self.config.field_mappings {
                    if let Some(value) = data.fields.get(&mapping.source_column) {
                        result.insert(mapping.output_field.clone(), value.clone());
                    }
                }
            }
        }

        result
    }

    /// Start the background reload task configured by `reload=`, if any.
    ///
    /// In watch mode the file-system watcher is created here, so a watcher that
    /// cannot be set up is reported as an error at startup instead of silently
    /// leaving the enrichment frozen.
    pub fn start_reload_task(&self) -> Result<(), EnrichmentError> {
        let Some(reload) = self.config.reload else {
            return Ok(());
        };
        let this = self.clone();
        match reload {
            ReloadMode::Interval(interval) => {
                thread::spawn(move || {
                    loop {
                        thread::sleep(interval);
                        this.reload();
                    }
                });
            }
            ReloadMode::Watch => {
                let path = self.config.source_file.clone();

                // Watch the directory of the configured path so that in-place
                // writes, atomic renames and symlink swaps are all seen. If the
                // path is a symlink, also watch the directory of the file it
                // currently resolves to, so edits made to the target are seen.
                let mut watched_dirs = vec![parent_dir(&path)];
                if let Ok(canonical) = path.canonicalize() {
                    let dir = parent_dir(&canonical);
                    if !watched_dirs.contains(&dir) {
                        watched_dirs.push(dir);
                    }
                }
                let (tx, rx) = std::sync::mpsc::channel::<DebounceEventResult>();
                let mut debouncer = new_debouncer(Duration::from_millis(100), None, tx)?;
                for dir in &watched_dirs {
                    debouncer.watch(dir, RecursiveMode::NonRecursive)?;
                }
                let mut last_seen = file_identity(&path);

                thread::spawn(move || {
                    // Keep the debouncer alive for as long as we are listening.
                    let _debouncer = debouncer;
                    while let Ok(result) = rx.recv() {
                        match result {
                            // Reading the file during a reload emits Access
                            // events of its own; reacting to those would make a
                            // file that is still being written reload on every
                            // debounce tick. Everything else, including a rescan
                            // after an inotify queue overflow, is a cue to
                            // re-check the file behind the configured path.
                            Ok(events)
                                if events
                                    .iter()
                                    .all(|e| matches!(e.kind, EventKind::Access(_))) =>
                            {
                                continue;
                            }
                            Ok(_) => {}
                            Err(errors) => {
                                for error in errors {
                                    eprintln!(
                                        "Enrichment watcher error for {}: {error}",
                                        path.display()
                                    );
                                }
                            }
                        }
                        // Reload only when the file actually changed.
                        let current = file_identity(&path);
                        if current == last_seen {
                            continue;
                        }
                        last_seen = current;
                        if current.is_some() {
                            this.reload();
                        } else {
                            eprintln!(
                                "Enrichment source {} is no longer readable; keeping previous data",
                                path.display()
                            );
                        }
                    }
                });
            }
        }
        Ok(())
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

/// Directory that contains `path`; a bare file name lives in `.`.
fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Identity of the file currently behind `path` (symlinks followed): a change
/// in any of these means the enrichment data on disk is not what was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    modified: Option<SystemTime>,
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let meta = fs::metadata(path).ok()?;
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, 0);
    Some(FileIdentity {
        dev,
        ino,
        len: meta.len(),
        modified: meta.modified().ok(),
    })
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
                enrichment.start_reload_task()?;
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
    MissingPrefix,
    LockPoisoned,
    Watch(notify_debouncer_full::notify::Error),
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
            Self::MissingPrefix => write!(
                f,
                "Missing prefix column in CSV (expected one of: {})",
                PREFIX_COLUMN_NAMES.join(", ")
            ),
            Self::LockPoisoned => write!(f, "Lock poisoned"),
            Self::Watch(e) => write!(f, "File watch error: {}", e),
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

impl From<notify_debouncer_full::notify::Error> for EnrichmentError {
    fn from(e: notify_debouncer_full::notify::Error) -> Self {
        Self::Watch(e)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::enrich::config::LookupKey;

    fn csv_file(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn prefix_column_is_available_as_a_field() {
        let path = csv_file(
            "rustflow_enrich_prefix.csv",
            "prefix,asn,org\n\
             10.0.0.0/8,13335,CLOUDFLARENET\n\
             10.1.0.0/16,2519,VECTANT\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path).unwrap();

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
    fn alternate_prefix_header_names_are_recognised() {
        // the prefix column need not be first, nor called "prefix"
        let path = csv_file(
            "rustflow_enrich_network.csv",
            "asn,network,org\n192,10.0.0.0/8,ACME\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path).unwrap();
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert_eq!(
            data.fields.get("network").map(String::as_str),
            Some("10.0.0.0/8")
        );
        assert_eq!(data.fields.get("asn").map(String::as_str), Some("192"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_values_are_omitted_rather_than_stored_blank() {
        let path = csv_file(
            "rustflow_enrich_empty.csv",
            "prefix,asn,org\n10.0.0.0/8,,ACME\n",
        );
        let tries = PrefixEnrichment::load_from_csv(&path).unwrap();
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        let (_, data) = tries.ipv4.get_lpm(&net).unwrap();
        assert!(data.fields.get("asn").is_none());
        assert_eq!(data.fields.get("org").map(String::as_str), Some("ACME"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn successful_load_updates_enrichment_metrics() {
        let path = csv_file(
            "rustflow_enrich_metrics.csv",
            "prefix,asn\n10.0.0.0/8,64512\n",
        );
        let source = path.display().to_string();
        let metrics = Arc::new(Metrics::new());
        let mut engine = EnrichmentEngine::new(Arc::clone(&metrics));
        let count = engine
            .add(EnrichmentConfig {
                lookup_type: LookupType::PrefixLookup,
                source_file: path.clone(),
                lookup_key: LookupKey::DstAddr,
                field_mappings: vec![FieldMapping {
                    source_column: "asn".to_string(),
                    output_field: "dst_asn".to_string(),
                }],
                reload: None,
            })
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(
            metrics
                .enrichment_loaded_rows
                .with_label_values(&[&source, "dst_addr"])
                .get(),
            1.0
        );
        assert!(
            metrics
                .enrichment_last_reload_timestamp_seconds
                .with_label_values(&[&source, "dst_addr"])
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
        let enrichment = PrefixEnrichment::new(
            EnrichmentConfig {
                lookup_type: LookupType::PrefixLookup,
                source_file: path.clone(),
                lookup_key: LookupKey::SrcAddr,
                field_mappings: vec![FieldMapping {
                    source_column: "asn".to_string(),
                    output_field: "src_asn".to_string(),
                }],
                reload: None,
            },
            &metrics,
        );
        assert_eq!(enrichment.load().unwrap(), 1);

        std::fs::write(&path, "garbage,asn\nfoo,bar\n").unwrap();
        enrichment.reload();

        let labels = [source.as_str(), "src_addr"];
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
            .add(EnrichmentConfig {
                lookup_type: LookupType::PrefixLookup,
                source_file: path.clone(),
                lookup_key: LookupKey::DstAddr,
                field_mappings: vec![],
                reload: None,
            })
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            metrics
                .enrichment_skipped_rows
                .with_label_values(&[&source, "dst_addr"])
                .get(),
            1.0
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn parent_dir_of_bare_file_name_is_cwd() {
        assert_eq!(parent_dir(Path::new("asn.csv")), PathBuf::from("."));
        assert_eq!(
            parent_dir(Path::new("/etc/rf/asn.csv")),
            PathBuf::from("/etc/rf")
        );
    }

    #[test]
    fn file_identity_changes_when_the_file_is_rewritten() {
        let path = csv_file("rustflow_enrich_identity.csv", "prefix,asn\n10.0.0.0/8,1\n");
        let before = file_identity(&path).unwrap();
        std::fs::write(&path, "prefix,asn\n10.0.0.0/8,1\n10.1.0.0/16,2\n").unwrap();
        assert_ne!(file_identity(&path).unwrap(), before);
        std::fs::remove_file(&path).ok();
        assert_eq!(file_identity(&path), None);
    }

    #[test]
    fn csv_without_prefix_column_is_rejected() {
        let path = csv_file("rustflow_enrich_no_prefix.csv", "garbage,asn\nfoo,bar\n");
        let Err(err) = PrefixEnrichment::load_from_csv(&path) else {
            panic!("expected a missing-prefix-column error");
        };
        assert!(matches!(err, EnrichmentError::MissingPrefix), "{err}");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn header_only_csv_loads_zero_rows() {
        let path = csv_file("rustflow_enrich_header_only.csv", "prefix,asn\n");
        let tries = PrefixEnrichment::load_from_csv(&path).unwrap();
        assert_eq!(tries.ipv4.len() + tries.ipv6.len(), 0);
        std::fs::remove_file(path).ok();
    }
}
