use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    PrefixLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchStrategy {
    #[default]
    Longest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKey {
    SrcAddr,
    DstAddr,
    NextHop,
    SamplerAddress,
}

impl LookupKey {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "src_addr" => Ok(Self::SrcAddr),
            "dst_addr" => Ok(Self::DstAddr),
            "next_hop" => Ok(Self::NextHop),
            "sampler_address" => Ok(Self::SamplerAddress),
            _ => Err(format!(
                "Unknown lookup key: '{}'. Valid keys: src_addr, dst_addr, next_hop, sampler_address",
                s
            )),
        }
    }

    pub fn extract(&self, flow: &CommonFlow) -> Option<IpAddr> {
        match self {
            Self::SrcAddr => flow.src_addr,
            Self::DstAddr => flow.dst_addr,
            Self::NextHop => flow.next_hop,
            Self::SamplerAddress => flow.sampler_address,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldMapping {
    pub source_column: String,
    pub output_field: String,
}

#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    pub lookup_type: LookupType,
    pub source_file: PathBuf,
    pub lookup_key: LookupKey,
    pub match_strategy: MatchStrategy,
    pub field_mappings: Vec<FieldMapping>,
    pub reload_interval: Option<Duration>,
}

pub fn parse_enrich_arg(arg: &str) -> Result<EnrichmentConfig, String> {
    let mut lookup_type = None;
    let mut source_file = None;
    let mut lookup_key = None;
    let mut match_strategy = MatchStrategy::default();
    let mut field_mappings = Vec::new();
    let mut reload_interval = None;

    for part in arg.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("Invalid format, expected key=value: '{}'", part))?;

        match key.trim() {
            "type" => {
                lookup_type = Some(match value.trim() {
                    "prefix_lookup" => LookupType::PrefixLookup,
                    other => {
                        return Err(format!(
                            "Unknown type: '{}'. Valid types: prefix_lookup",
                            other
                        ));
                    }
                });
            }
            "source" => {
                source_file = Some(PathBuf::from(value.trim()));
            }
            "key" => {
                lookup_key = Some(LookupKey::from_str(value.trim())?);
            }
            "match" => {
                match_strategy = match value.trim() {
                    "longest" => MatchStrategy::Longest,
                    other => {
                        return Err(format!(
                            "Unknown match strategy: '{}'. Valid strategies: longest",
                            other
                        ));
                    }
                };
            }
            "fields" => {
                for field_spec in value.split(';') {
                    let field_spec = field_spec.trim();
                    if field_spec.is_empty() {
                        continue;
                    }
                    let (src, dst) = field_spec.split_once(':').ok_or_else(|| {
                        format!(
                            "Invalid field mapping, expected source:output: '{}'",
                            field_spec
                        )
                    })?;
                    field_mappings.push(FieldMapping {
                        source_column: src.trim().to_string(),
                        output_field: dst.trim().to_string(),
                    });
                }
            }
            "reload" => {
                let duration = duration_str::parse(value.trim())
                    .map_err(|e| format!("Invalid reload duration '{}': {}", value, e))?;
                reload_interval = Some(duration);
            }
            other => return Err(format!("Unknown parameter: '{}'", other)),
        }
    }

    if field_mappings.is_empty() {
        return Err("Missing 'fields' parameter or no field mappings specified".to_string());
    }

    Ok(EnrichmentConfig {
        lookup_type: lookup_type.ok_or("Missing 'type' parameter")?,
        source_file: source_file.ok_or("Missing 'source' parameter")?,
        lookup_key: lookup_key.ok_or("Missing 'key' parameter")?,
        match_strategy,
        field_mappings,
        reload_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let arg = "type=prefix_lookup,source=test.csv,key=dst_addr,match=longest,fields=account:dst_account";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(config.lookup_type, LookupType::PrefixLookup);
        assert_eq!(config.source_file, PathBuf::from("test.csv"));
        assert!(matches!(config.lookup_key, LookupKey::DstAddr));
        assert_eq!(config.field_mappings.len(), 1);
        assert_eq!(config.field_mappings[0].source_column, "account");
        assert_eq!(config.field_mappings[0].output_field, "dst_account");
        assert!(config.reload_interval.is_none());
    }

    #[test]
    fn test_parse_with_reload() {
        let arg =
            "type=prefix_lookup,source=test.csv,key=src_addr,fields=region:src_region,reload=30s";
        let config = parse_enrich_arg(arg).unwrap();
        assert!(matches!(config.lookup_key, LookupKey::SrcAddr));
        assert_eq!(config.reload_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_multiple_fields() {
        let arg = "type=prefix_lookup,source=test.csv,key=dst_addr,fields=account:dst_account;region:dst_region;owner:dst_owner";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(config.field_mappings.len(), 3);
    }

    #[test]
    fn test_parse_missing_type() {
        let arg = "source=test.csv,key=dst_addr,fields=a:b";
        assert!(parse_enrich_arg(arg).is_err());
    }

    #[test]
    fn test_parse_missing_fields() {
        let arg = "type=prefix_lookup,source=test.csv,key=dst_addr";
        assert!(parse_enrich_arg(arg).is_err());
    }
}
