use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::{Error, Key, KeyType, ReloadPolicy, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvLookup {
    Prefix {
        prefix_column: String,
    },
    Exact {
        key_column: String,
        key_type: KeyType,
    },
}

impl CsvLookup {
    pub fn column(&self) -> &str {
        match self {
            Self::Prefix { prefix_column } => prefix_column,
            Self::Exact { key_column, .. } => key_column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFormat {
    Csv(CsvLookup),
    Mmdb,
}

#[derive(Debug, Clone)]
pub struct SourceConfig {
    source: PathBuf,
    format: SourceFormat,
    reload: ReloadPolicy,
    columns: Vec<String>,
}

impl SourceConfig {
    pub fn new(
        source: PathBuf,
        format: SourceFormat,
        columns: Vec<String>,
        reload: ReloadPolicy,
    ) -> Result<Self> {
        if source.as_os_str().is_empty() {
            return Err(Error::Config("Empty source".into()));
        }

        if columns.is_empty() {
            return Err(Error::Config(
                "At least one source column is required".into(),
            ));
        }

        let mut seen = HashSet::new();
        for column in &columns {
            if column.trim().is_empty() || !seen.insert(column) {
                return Err(Error::Config(
                    "Source columns must be nonempty and unique".into(),
                ));
            }
        }

        if let SourceFormat::Csv(options) = &format
            && options.column().trim().is_empty()
        {
            return Err(Error::Config("Empty CSV key column".into()));
        }

        Ok(Self {
            source: std::path::absolute(source)?,
            format,
            columns,
            reload,
        })
    }

    pub fn source(&self) -> &Path {
        &self.source
    }
    pub fn format(&self) -> &SourceFormat {
        &self.format
    }
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
    pub fn reload(&self) -> ReloadPolicy {
        self.reload
    }
}

pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);

pub const MIN_INTERVAL: Duration = Duration::from_secs(10);

impl FromStr for ReloadPolicy {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "never" => Self::Never,
            "watch" => Self::Watch {
                debounce: DEFAULT_DEBOUNCE,
            },
            _ => {
                let interval = duration_str::parse(value).map_err(|e| {
                    Error::Config(format!("Invalid reload duration '{value}': {e}"))
                })?;
                if interval < MIN_INTERVAL {
                    return Err(Error::Config(format!(
                        "Reload interval '{value}' must be at least {MIN_INTERVAL:?}"
                    )));
                }
                Self::Interval(interval)
            }
        })
    }
}

/// The flow field a lookup key is taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKey {
    SrcAddr,
    DstAddr,
    NextHop,
    BgpNextHop,
    SamplerAddress,
    Proto,
    SrcPort,
    DstPort,
    InIf,
    OutIf,
    SrcAs,
    DstAs,
    SrcVlan,
    DstVlan,
    Etype,
}

impl LookupKey {
    pub const NAMES: &[(&str, Self)] = &[
        ("src_addr", Self::SrcAddr),
        ("dst_addr", Self::DstAddr),
        ("next_hop", Self::NextHop),
        ("bgp_next_hop", Self::BgpNextHop),
        ("sampler_address", Self::SamplerAddress),
        ("proto", Self::Proto),
        ("src_port", Self::SrcPort),
        ("dst_port", Self::DstPort),
        ("in_if", Self::InIf),
        ("out_if", Self::OutIf),
        ("src_as", Self::SrcAs),
        ("dst_as", Self::DstAs),
        ("src_vlan", Self::SrcVlan),
        ("dst_vlan", Self::DstVlan),
        ("etype", Self::Etype),
    ];

    /// The kind of key this field produces: addresses are `Ip`, everything
    /// else is `Number`.
    pub fn key_type(self) -> KeyType {
        match self {
            Self::SrcAddr
            | Self::DstAddr
            | Self::NextHop
            | Self::BgpNextHop
            | Self::SamplerAddress => KeyType::Ip,
            _ => KeyType::Number,
        }
    }

    /// The field's value as a lookup key, if the flow has it.
    pub fn extract(self, flow: &CommonFlow) -> Option<Key<'static>> {
        fn ip(addr: Option<IpAddr>) -> Option<Key<'static>> {
            addr.map(Key::Ip)
        }
        fn number(value: Option<impl Into<u64>>) -> Option<Key<'static>> {
            value.map(|v| Key::Number(v.into()))
        }
        match self {
            Self::SrcAddr => ip(flow.src_addr),
            Self::DstAddr => ip(flow.dst_addr),
            Self::NextHop => ip(flow.next_hop),
            Self::BgpNextHop => ip(flow.bgp_next_hop),
            Self::SamplerAddress => ip(flow.sampler_address),
            Self::Proto => number(flow.proto),
            Self::SrcPort => number(flow.src_port),
            Self::DstPort => number(flow.dst_port),
            Self::InIf => number(flow.in_if),
            Self::OutIf => number(flow.out_if),
            Self::SrcAs => number(flow.src_as),
            Self::DstAs => number(flow.dst_as),
            Self::SrcVlan => number(flow.src_vlan),
            Self::DstVlan => number(flow.dst_vlan),
            Self::Etype => number(flow.etype),
        }
    }
}

impl FromStr for LookupKey {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, key)| *key)
            .ok_or_else(|| {
                let names: Vec<_> = Self::NAMES.iter().map(|(name, _)| *name).collect();
                Error::Config(format!(
                    "Unknown lookup key '{value}'. Valid keys: {}",
                    names.join(", ")
                ))
            })
    }
}

/// One output field: the flow field to look up, the source column to read,
/// and the name to emit it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMapping {
    pub key: LookupKey,
    pub source_column: String,
    pub output_field: String,
}

/// One `--enrich` argument: a source and the fields it produces.
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    pub source: SourceConfig,
    pub mappings: Vec<FieldMapping>,
}

const PARAMETERS: &[&str] = &[
    "type",
    "format",
    "source",
    "prefix_column",
    "key_column",
    "fields",
    "reload",
];

#[derive(Clone, Copy)]
enum Kind {
    Prefix,
    Exact,
}

impl FromStr for Kind {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "prefix_lookup" => Ok(Self::Prefix),
            "exact" => Ok(Self::Exact),
            other => Err(Error::Config(format!("Unknown type '{other}'"))),
        }
    }
}

#[derive(Clone, Copy)]
enum Format {
    Csv,
    Mmdb,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("csv") {
            Ok(Self::Csv)
        } else if value.eq_ignore_ascii_case("mmdb") {
            Ok(Self::Mmdb)
        } else {
            Err(Error::Config(format!("Unknown format '{value}'")))
        }
    }
}

/// Parse one `fields` value: groups separated by `;`, each
/// `<key>@<source>:<output>[|<source>:<output>...]`.
fn parse_field_mappings(value: &str) -> Result<Vec<FieldMapping>> {
    let mut mappings = Vec::new();
    for group in value.split(';').map(str::trim).filter(|g| !g.is_empty()) {
        let (key, specs) = group.split_once('@').ok_or_else(|| {
            Error::Config(format!(
                "Invalid field group, expected <key>@<source>:<output>[|<source>:<output>...]: '{group}'"
            ))
        })?;
        let key: LookupKey = key.trim().parse()?;
        let mut any = false;
        for spec in specs.split('|').map(str::trim).filter(|s| !s.is_empty()) {
            let (source_column, output_field) = spec
                .split_once(':')
                .map(|(s, o)| (s.trim(), o.trim()))
                .filter(|(s, o)| !s.is_empty() && !o.is_empty())
                .ok_or_else(|| {
                    Error::Config(format!(
                        "Invalid field mapping, expected source:output: '{spec}'"
                    ))
                })?;
            mappings.push(FieldMapping {
                key,
                source_column: source_column.to_owned(),
                output_field: output_field.to_owned(),
            });
            any = true;
        }
        if !any {
            return Err(Error::Config(format!(
                "Field group has no mappings: '{group}'"
            )));
        }
    }
    if mappings.is_empty() {
        return Err(Error::Config("'fields' has no field mappings".into()));
    }
    Ok(mappings)
}

pub fn parse_enrich_arg(arg: &str) -> Result<EnrichmentConfig> {
    let mut params = HashMap::new();
    for part in arg.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| Error::Config(format!("Expected key=value: '{part}'")))?;
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            return Err(Error::Config(format!("Empty '{key}' parameter")));
        }
        if !PARAMETERS.contains(&key) {
            return Err(Error::Config(format!("Unknown parameter '{key}'")));
        }
        if params.insert(key, value).is_some() {
            return Err(Error::Config(format!("Duplicate parameter '{key}'")));
        }
    }
    let required = |key: &str| {
        params
            .get(key)
            .copied()
            .ok_or_else(|| Error::Config(format!("Missing '{key}' parameter")))
    };
    let forbid =
        |keys: &[&str], context: &str| match keys.iter().find(|key| params.contains_key(*key)) {
            Some(key) => Err(Error::Config(format!("'{key}' is not valid for {context}"))),
            None => Ok(()),
        };
    let kind: Kind = required("type")?.parse()?;
    let source = PathBuf::from(required("source")?);
    let format: Format = params
        .get("format")
        .copied()
        .or_else(|| source.extension()?.to_str())
        .ok_or_else(|| {
            Error::Config("Specify format=csv or format=mmdb when source has no extension".into())
        })?
        .parse()?;
    let mappings = parse_field_mappings(required("fields")?)?;

    // Every key of one source must produce the same kind of lookup key.
    let key_type = mappings[0].key.key_type();
    if mappings.iter().any(|m| m.key.key_type() != key_type) {
        return Err(Error::Config(
            "All lookup keys of one source must be addresses or all numbers".into(),
        ));
    }
    if matches!(kind, Kind::Prefix) && key_type != KeyType::Ip {
        return Err(Error::Config(
            "prefix_lookup keys must be address fields".into(),
        ));
    }
    let format = match (format, kind) {
        (Format::Csv, Kind::Prefix) => {
            forbid(&["key_column"], "CSV prefix_lookup")?;
            SourceFormat::Csv(CsvLookup::Prefix {
                prefix_column: required("prefix_column")?.into(),
            })
        }
        (Format::Csv, Kind::Exact) => {
            forbid(&["prefix_column"], "CSV exact lookup")?;
            SourceFormat::Csv(CsvLookup::Exact {
                key_column: required("key_column")?.into(),
                key_type,
            })
        }
        (Format::Mmdb, Kind::Prefix) => {
            forbid(&["prefix_column", "key_column"], "MMDB")?;
            SourceFormat::Mmdb
        }
        (Format::Mmdb, Kind::Exact) => {
            return Err(Error::Config("MMDB supports only prefix_lookup".into()));
        }
    };
    let reload = params
        .get("reload")
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or_default();
    let mut columns: Vec<String> = Vec::new();
    for mapping in &mappings {
        if !columns.contains(&mapping.source_column) {
            columns.push(mapping.source_column.clone());
        }
    }
    Ok(EnrichmentConfig {
        source: SourceConfig::new(source, format, columns, reload)?,
        mappings,
    })
}
