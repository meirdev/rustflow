use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use prefix_trie::PrefixMap;
use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, FieldMapping, LookupType};

/// Column names that are recognized as prefix/network columns in CSV files
const PREFIX_COLUMN_NAMES: &[&str] = &["prefix", "network", "cidr"];

#[derive(Debug, Clone)]
pub struct PrefixData {
    pub fields: HashMap<String, String>,
}

struct PrefixTries {
    ipv4: PrefixMap<Ipv4Net, PrefixData>,
    ipv6: PrefixMap<Ipv6Net, PrefixData>,
}

impl PrefixTries {
    fn new() -> Self {
        Self {
            ipv4: PrefixMap::new(),
            ipv6: PrefixMap::new(),
        }
    }
}

pub struct PrefixEnrichment {
    config: EnrichmentConfig,
    tries: Arc<RwLock<PrefixTries>>,
}

impl PrefixEnrichment {
    pub fn new(config: EnrichmentConfig) -> Self {
        Self {
            config,
            tries: Arc::new(RwLock::new(PrefixTries::new())),
        }
    }

    pub fn load(&self) -> Result<usize, EnrichmentError> {
        let new_tries =
            Self::load_from_file(&self.config.source_file, &self.config.field_mappings)?;
        let count = new_tries.ipv4.len() + new_tries.ipv6.len();

        let mut tries = self
            .tries
            .write()
            .map_err(|_| EnrichmentError::LockPoisoned)?;
        *tries = new_tries;

        Ok(count)
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
            .unwrap_or(0);

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

    pub fn start_reload_task(&self) {
        if let Some(interval) = self.config.reload_interval {
            let tries = Arc::clone(&self.tries);
            let path = self.config.source_file.clone();
            let field_mappings = self.config.field_mappings.clone();

            thread::spawn(move || {
                loop {
                    thread::sleep(interval);

                    match Self::load_from_file(&path, &field_mappings) {
                        Ok(new_tries) => {
                            let count = new_tries.ipv4.len() + new_tries.ipv6.len();
                            if let Ok(mut guard) = tries.write() {
                                *guard = new_tries;
                                eprintln!(
                                    "Reloaded {} prefix entries from {}",
                                    count,
                                    path.display()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to reload enrichment from {}: {}", path.display(), e);
                        }
                    }
                }
            });
        }
    }
}

pub struct EnrichmentEngine {
    prefix_enrichments: Vec<PrefixEnrichment>,
    output_fields: Vec<String>,
}

impl EnrichmentEngine {
    pub fn new() -> Self {
        Self {
            prefix_enrichments: Vec::new(),
            output_fields: Vec::new(),
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
                let enrichment = PrefixEnrichment::new(config);
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

impl Default for EnrichmentEngine {
    fn default() -> Self {
        Self::new()
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
            Self::MissingPrefix => write!(f, "Missing prefix column in CSV"),
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

    use super::*;

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
}
