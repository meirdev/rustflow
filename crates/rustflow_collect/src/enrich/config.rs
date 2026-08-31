use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    PrefixLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKey {
    SrcAddr,
    DstAddr,
    NextHop,
    SamplerAddress,
}

impl LookupKey {
    /// Number of variants; `index()` is always below this.
    pub const COUNT: usize = 4;

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

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMapping {
    /// Flow field whose address is looked up in the datasource.
    pub key: LookupKey,
    /// Column (CSV) or dotted path (MaxMind DB) in the datasource.
    pub source_column: String,
    /// Name of the emitted field.
    pub output_field: String,
}

#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    pub lookup_type: LookupType,
    pub source_file: PathBuf,
    pub field_mappings: Vec<FieldMapping>,
    /// Name of the CSV column holding the prefix. Required for CSV sources,
    /// not applicable to MaxMind DB sources.
    pub prefix_column: Option<String>,
    pub reload_interval: Option<Duration>,
}

/// Split the argument on `,` into `(name, value)` parameters.
fn split_parameters(arg: &str) -> Result<Vec<(&str, &str)>, String> {
    arg.split(',')
        .map(|part| {
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| format!("Invalid format, expected key=value: '{}'", part))?;
            let name = name.trim();
            if name.is_empty() {
                return Err(format!("Invalid format, expected key=value: '{}'", part));
            }
            Ok((name, value.trim()))
        })
        .collect()
}

/// Parse one `fields` value.
///
/// Groups are separated by `;`, and each group is
/// `<key>@<mapping>[|<mapping>...]` where a mapping is `<source>:<output>`.
/// Every group must name its key.
fn parse_field_mappings(value: &str) -> Result<Vec<FieldMapping>, String> {
    let mut mappings = Vec::new();

    for group in value.split(';') {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }

        let (key, specs) = group.split_once('@').ok_or_else(|| {
            format!(
                "Invalid field group, expected <key>@<source>:<output>[|<source>:<output>...]: '{}'",
                group
            )
        })?;
        let key = LookupKey::from_str(key.trim())?;

        let mut any = false;
        for spec in specs.split('|') {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let (src, dst) = spec.split_once(':').ok_or_else(|| {
                format!("Invalid field mapping, expected source:output: '{}'", spec)
            })?;
            let (src, dst) = (src.trim(), dst.trim());
            if src.is_empty() || dst.is_empty() {
                return Err(format!(
                    "Invalid field mapping, expected source:output: '{}'",
                    spec
                ));
            }
            mappings.push(FieldMapping {
                key,
                source_column: src.to_string(),
                output_field: dst.to_string(),
            });
            any = true;
        }

        if !any {
            return Err(format!("Field group has no mappings: '{}'", group));
        }
    }

    Ok(mappings)
}

pub fn parse_enrich_arg(arg: &str) -> Result<EnrichmentConfig, String> {
    let mut lookup_type = None;
    let mut source_file = None;
    let mut field_mappings = Vec::new();
    let mut prefix_column = None;
    let mut reload_interval = None;

    for (key, value) in split_parameters(arg)? {
        match key {
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
            "fields" => {
                field_mappings.extend(parse_field_mappings(value)?);
            }
            "prefix_column" => {
                let name = value.trim();
                if name.is_empty() {
                    return Err("Empty 'prefix_column' parameter".to_string());
                }
                prefix_column = Some(name.to_string());
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

    let source_file: PathBuf = source_file.ok_or("Missing 'source' parameter")?;
    let is_csv = source_file
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"));
    match (&prefix_column, is_csv) {
        (None, true) => {
            return Err("Missing 'prefix_column' parameter (required for CSV sources)".to_string());
        }
        (Some(_), false) => {
            return Err("'prefix_column' only applies to CSV sources".to_string());
        }
        _ => {}
    }

    Ok(EnrichmentConfig {
        lookup_type: lookup_type.ok_or("Missing 'type' parameter")?,
        source_file,
        field_mappings,
        prefix_column,
        reload_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(key: LookupKey, src: &str, dst: &str) -> FieldMapping {
        FieldMapping {
            key,
            source_column: src.to_string(),
            output_field: dst.to_string(),
        }
    }

    #[test]
    fn test_parse_basic() {
        let arg = "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=dst_addr@account:dst_account";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(config.lookup_type, LookupType::PrefixLookup);
        assert_eq!(config.source_file, PathBuf::from("test.csv"));
        assert_eq!(
            config.field_mappings,
            vec![mapping(LookupKey::DstAddr, "account", "dst_account")]
        );
        assert_eq!(config.prefix_column.as_deref(), Some("prefix"));
        assert!(config.reload_interval.is_none());
    }

    #[test]
    fn test_parse_with_reload() {
        let arg = "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=src_addr@region:src_region,reload=30s";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(
            config.field_mappings,
            vec![mapping(LookupKey::SrcAddr, "region", "src_region")]
        );
        assert_eq!(config.reload_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_multiple_fields_in_one_group() {
        let arg = "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=dst_addr@account:dst_account|region:dst_region|owner:dst_owner";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(
            config.field_mappings,
            vec![
                mapping(LookupKey::DstAddr, "account", "dst_account"),
                mapping(LookupKey::DstAddr, "region", "dst_region"),
                mapping(LookupKey::DstAddr, "owner", "dst_owner"),
            ]
        );
    }

    #[test]
    fn test_parse_multiple_keys() {
        let arg = "type=prefix_lookup,source=GeoLite2-City.mmdb,fields=src_addr@country.iso_code:src_country|city.names.en:src_city;dst_addr@country.iso_code:dst_country|city.names.en:dst_city,reload=1h";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(
            config.field_mappings,
            vec![
                mapping(LookupKey::SrcAddr, "country.iso_code", "src_country"),
                mapping(LookupKey::SrcAddr, "city.names.en", "src_city"),
                mapping(LookupKey::DstAddr, "country.iso_code", "dst_country"),
                mapping(LookupKey::DstAddr, "city.names.en", "dst_city"),
            ]
        );
        assert_eq!(config.reload_interval, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_fields_before_source() {
        let arg = "fields=src_addr@asn:src_asn|org:src_org,source=asn.csv,prefix_column=net,type=prefix_lookup";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(config.source_file, PathBuf::from("asn.csv"));
        assert_eq!(config.field_mappings.len(), 2);
    }

    #[test]
    fn test_parse_prefix_column() {
        let arg =
            "type=prefix_lookup,source=test.csv,prefix_column=subnet,fields=dst_addr@asn:dst_asn";
        let config = parse_enrich_arg(arg).unwrap();
        assert_eq!(config.prefix_column.as_deref(), Some("subnet"));

        let arg = "type=prefix_lookup,source=test.csv,prefix_column=,fields=dst_addr@asn:dst_asn";
        assert!(parse_enrich_arg(arg).is_err());
    }

    #[test]
    fn test_prefix_column_is_required_for_csv_only() {
        let arg = "type=prefix_lookup,source=test.csv,fields=dst_addr@asn:dst_asn";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("Missing 'prefix_column'"), "{}", err);

        // extension match is case-insensitive
        let arg = "type=prefix_lookup,source=TEST.CSV,fields=dst_addr@asn:dst_asn";
        assert!(parse_enrich_arg(arg).is_err());

        let arg = "type=prefix_lookup,source=geo.mmdb,fields=dst_addr@country.iso_code:dst_country";
        let config = parse_enrich_arg(arg).unwrap();
        assert!(config.prefix_column.is_none());

        let arg = "type=prefix_lookup,source=geo.mmdb,prefix_column=x,fields=dst_addr@country.iso_code:dst_country";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("only applies to CSV"), "{}", err);
    }

    #[test]
    fn test_parse_group_without_key_is_rejected() {
        let arg =
            "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=account:dst_account";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("<key>@"), "{}", err);

        let arg = "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=dst_addr@a:b;region:dst_region";
        assert!(parse_enrich_arg(arg).is_err());
    }

    #[test]
    fn test_parse_unknown_key_is_rejected() {
        let arg = "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields=nope@account:dst_account";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("Unknown lookup key"), "{}", err);
    }

    #[test]
    fn test_parse_bad_mapping_is_rejected() {
        for fields in [
            "dst_addr@account",
            "dst_addr@:x",
            "dst_addr@x:",
            "dst_addr@",
        ] {
            let arg = format!(
                "type=prefix_lookup,source=test.csv,prefix_column=prefix,fields={}",
                fields
            );
            assert!(parse_enrich_arg(&arg).is_err(), "{}", fields);
        }
    }

    #[test]
    fn test_removed_key_parameter_is_rejected() {
        let arg = "type=prefix_lookup,source=test.csv,key=dst_addr,fields=dst_addr@a:b";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("Unknown parameter: 'key'"), "{}", err);
    }

    #[test]
    fn test_split_parameters() {
        assert_eq!(
            split_parameters("type=prefix_lookup,source=x.csv,fields=src_addr@a:b|c:d,reload=10s")
                .unwrap(),
            vec![
                ("type", "prefix_lookup"),
                ("source", "x.csv"),
                ("fields", "src_addr@a:b|c:d"),
                ("reload", "10s"),
            ]
        );
        assert_eq!(
            split_parameters(" type = x , source = y ").unwrap(),
            vec![("type", "x"), ("source", "y")]
        );
        for bad in ["type", "a=b,c", "=x"] {
            assert!(split_parameters(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn test_comma_inside_fields_is_rejected() {
        let arg = "type=prefix_lookup,source=x.mmdb,fields=src_addr@a:b,c:d";
        let err = parse_enrich_arg(arg).unwrap_err();
        assert!(err.contains("expected key=value: 'c:d'"), "{}", err);
    }

    #[test]
    fn test_parse_missing_type() {
        let arg = "source=test.csv,prefix_column=prefix,fields=dst_addr@a:b";
        assert!(parse_enrich_arg(arg).is_err());
    }

    #[test]
    fn test_parse_missing_fields() {
        let arg = "type=prefix_lookup,source=test.csv";
        assert!(parse_enrich_arg(arg).is_err());
    }
}
