use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use crate::enrich::{Error, Key, KeyType, ReloadPolicy, Result};

/// The most lookup keys one group may combine.
pub const MAX_KEYS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvLookup {
    Prefix,
    /// One key type per key column.
    Exact(Vec<KeyType>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFormat {
    Csv {
        key_columns: Vec<String>,
        lookup: CsvLookup,
    },
    Mmdb,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    File(PathBuf),
    Command {
        program: PathBuf,
        timeout: Duration,
    },
}

impl Origin {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(path) | Self::Command { program: path, .. } => path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceConfig {
    origin: Origin,
    format: SourceFormat,
    reload: ReloadPolicy,
    columns: Vec<String>,
}

impl SourceConfig {
    pub fn new(
        origin: Origin,
        format: SourceFormat,
        columns: Vec<String>,
        reload: ReloadPolicy,
    ) -> Result<Self> {
        if origin.path().as_os_str().is_empty() {
            return Err(Error::Config("Empty source".into()));
        }

        if let Origin::Command { timeout, .. } = &origin {
            if format == SourceFormat::Mmdb {
                return Err(Error::Config("A command supports only CSV".into()));
            }
            if matches!(reload, ReloadPolicy::Watch { .. }) {
                return Err(Error::Config(
                    "A command cannot be watched; use a reload interval".into(),
                ));
            }
            if timeout.is_zero() {
                return Err(Error::Config("Command timeout must not be zero".into()));
            }
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

        if let SourceFormat::Csv { key_columns, .. } = &format
            && (key_columns.is_empty() || key_columns.iter().any(|c| c.trim().is_empty()))
        {
            return Err(Error::Config("Empty CSV key column".into()));
        }

        let origin = match origin {
            Origin::File(path) => Origin::File(std::path::absolute(path)?),
            Origin::Command { program, timeout } => Origin::Command {
                program: std::path::absolute(program)?,
                timeout,
            },
        };

        Ok(Self {
            origin,
            format,
            columns,
            reload,
        })
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    /// The file, or the executable of a command.
    pub fn source(&self) -> &Path {
        self.origin.path()
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

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Clone, Copy)]
pub struct LookupKey {
    name: &'static str,
    key_type: KeyType,
    extract: fn(&CommonFlow) -> Option<Key>,
}

macro_rules! lookup_fields {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        lookup_fields!(@fields [] $( $name : $kind $presence, )*);
    };
    (@fields [$($acc:tt)*] $name:ident : FlowType $presence:ident, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)*] $($rest)*);
    };
    (@fields [$($acc:tt)*] $name:ident : Timestamp $presence:ident, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)*] $($rest)*);
    };
    (@fields [$($acc:tt)*] $name:ident : Mac $presence:ident, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)*] $($rest)*);
    };
    (@fields [$($acc:tt)*] $name:ident : Ip optional, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)* LookupKey {
            name: stringify!($name),
            key_type: KeyType::Ip,
            extract: |flow| flow.$name.map(Key::Ip),
        },] $($rest)*);
    };
    (@fields [$($acc:tt)*] $name:ident : $kind:ident optional, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)* LookupKey {
            name: stringify!($name),
            key_type: KeyType::Number,
            extract: |flow| flow.$name.map(|value| Key::Number(value.into())),
        },] $($rest)*);
    };
    (@fields [$($acc:tt)*] $name:ident : $kind:ident required, $($rest:tt)*) => {
        lookup_fields!(@fields [$($acc)* LookupKey {
            name: stringify!($name),
            key_type: KeyType::Number,
            extract: |flow| Some(Key::Number(flow.$name.into())),
        },] $($rest)*);
    };
    (@fields [$($acc:tt)*]) => {
        const LOOKUP_KEYS: &[LookupKey] = &[$($acc)*];
    };
}
for_each_flow_field!(lookup_fields);

impl LookupKey {
    pub fn all() -> impl Iterator<Item = Self> {
        LOOKUP_KEYS.iter().copied()
    }

    pub fn name(self) -> &'static str {
        self.name
    }

    pub fn key_type(self) -> KeyType {
        self.key_type
    }

    pub fn extract(self, flow: &CommonFlow) -> Option<Key> {
        (self.extract)(flow)
    }
}

impl PartialEq for LookupKey {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for LookupKey {}

impl fmt::Debug for LookupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for LookupKey {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::all().find(|key| key.name() == value).ok_or_else(|| {
            let names: Vec<_> = Self::all().map(LookupKey::name).collect();
            Error::Config(format!(
                "Unknown lookup key '{value}'. Valid keys: {}",
                names.join(", ")
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMapping {
    /// The flow fields that together form the lookup key.
    pub keys: Vec<LookupKey>,
    pub source_column: String,
    pub output_field: String,
}

#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    pub source: SourceConfig,
    pub mappings: Vec<FieldMapping>,
}

const PARAMETERS: &[&str] = &[
    "type",
    "format",
    "source",
    "command",
    "timeout",
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

fn parse_field_mappings(value: &str) -> Result<Vec<FieldMapping>> {
    let mut mappings = Vec::new();

    for group in value.split(';').map(str::trim).filter(|g| !g.is_empty()) {
        let (key, specs) = group.split_once('@').ok_or_else(|| {
            Error::Config(format!(
                "Invalid field group, expected <key>@<source>:<output>[|<source>:<output>...]: '{group}'"
            ))
        })?;

        let keys = key
            .split('+')
            .map(|key| key.trim().parse())
            .collect::<Result<Vec<LookupKey>>>()?;
        if keys.len() > MAX_KEYS {
            return Err(Error::Config(format!(
                "At most {MAX_KEYS} lookup keys can be combined: '{key}'"
            )));
        }
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
                keys: keys.clone(),
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
    let origin = match (params.get("source"), params.get("command")) {
        (Some(path), None) => {
            forbid(&["timeout"], "a file source")?;
            Origin::File(PathBuf::from(path))
        }
        (None, Some(program)) => Origin::Command {
            program: PathBuf::from(program),
            timeout: match params.get("timeout") {
                Some(value) => duration_str::parse(value)
                    .map_err(|e| Error::Config(format!("Invalid timeout '{value}': {e}")))?,
                None => DEFAULT_TIMEOUT,
            },
        },
        (Some(_), Some(_)) => {
            return Err(Error::Config(
                "'source' and 'command' are mutually exclusive".into(),
            ));
        }
        (None, None) => {
            return Err(Error::Config(
                "Missing 'source' or 'command' parameter".into(),
            ));
        }
    };

    let format: Format = match (params.get("format"), &origin) {
        (Some(format), _) => format.parse()?,
        (None, Origin::File(path)) => path
            .extension()
            .and_then(|extension| extension.to_str())
            .ok_or_else(|| {
                Error::Config(
                    "Specify format=csv or format=mmdb when source has no extension".into(),
                )
            })?
            .parse()?,
        // An executable's extension says nothing about what it prints.
        (None, Origin::Command { .. }) => Format::Csv,
    };

    let mappings = parse_field_mappings(required("fields")?)?;

    let key_types: Vec<KeyType> = mappings[0].keys.iter().map(|key| key.key_type()).collect();
    if mappings.iter().any(|m| {
        !m.keys
            .iter()
            .map(|key| key.key_type())
            .eq(key_types.iter().copied())
    }) {
        return Err(Error::Config(
            "All lookup groups of one source must use the same key types in the same order".into(),
        ));
    }

    if matches!(kind, Kind::Prefix) && key_types != [KeyType::Ip] {
        return Err(Error::Config(
            "prefix_lookup takes a single address field as key".into(),
        ));
    }

    let format = match (format, kind) {
        (Format::Csv, kind) => {
            let key_columns: Vec<String> = required("key_column")?
                .split('+')
                .map(|column| column.trim().to_owned())
                .collect();
            if key_columns.len() != key_types.len() {
                return Err(Error::Config(format!(
                    "'key_column' lists {} columns for {} lookup keys",
                    key_columns.len(),
                    key_types.len()
                )));
            }
            SourceFormat::Csv {
                key_columns,
                lookup: match kind {
                    Kind::Prefix => CsvLookup::Prefix,
                    Kind::Exact => CsvLookup::Exact(key_types),
                },
            }
        }
        (Format::Mmdb, Kind::Prefix) => {
            forbid(&["key_column"], "MMDB")?;
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
        source: SourceConfig::new(origin, format, columns, reload)?,
        mappings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(mapping: &FieldMapping) -> Vec<&str> {
        mapping.keys.iter().map(|key| key.name()).collect()
    }

    #[test]
    fn composite_keys_pair_columns_with_flow_fields() {
        let config = parse_enrich_arg(
            "type=exact,source=ifnames.csv,key_column=exporter+ifindex,\
             fields=sampler_address+in_if@name:in_if_name;sampler_address+out_if@name:out_if_name",
        )
        .unwrap();

        assert_eq!(
            config.source.format(),
            &SourceFormat::Csv {
                key_columns: vec!["exporter".into(), "ifindex".into()],
                lookup: CsvLookup::Exact(vec![KeyType::Ip, KeyType::Number]),
            }
        );
        assert_eq!(names(&config.mappings[0]), ["sampler_address", "in_if"]);
        assert_eq!(names(&config.mappings[1]), ["sampler_address", "out_if"]);
    }

    #[test]
    fn composite_keys_are_validated() {
        let error = |arg: &str| parse_enrich_arg(arg).unwrap_err().to_string();

        assert!(
            error(
                "type=exact,source=a.csv,key_column=exporter,fields=sampler_address+in_if@name:n"
            )
            .contains("lists 1 columns for 2 lookup keys")
        );
        assert!(
            error(
                "type=exact,source=a.csv,key_column=a+b,\
                 fields=sampler_address+in_if@name:n;in_if+sampler_address@name:m"
            )
            .contains("same key types in the same order")
        );
        assert!(
            error("type=prefix_lookup,source=a.csv,key_column=a+b,fields=src_addr+in_if@name:n")
                .contains("single address field")
        );
        assert!(
            error(
                "type=exact,source=a.csv,key_column=a+b+c+d+e,\
                 fields=in_if+out_if+src_port+dst_port+proto@name:n"
            )
            .contains("At most 4 lookup keys")
        );
    }

    #[test]
    fn command_is_a_csv_source_with_a_timeout() {
        let parse = |extra: &str| {
            parse_enrich_arg(&format!(
                "type=exact,command=/opt/ifnames.sh,key_column=number,fields=proto@name:n{extra}"
            ))
            .unwrap()
        };

        let config = parse("");
        assert_eq!(
            config.source.origin(),
            &Origin::Command {
                program: "/opt/ifnames.sh".into(),
                timeout: DEFAULT_TIMEOUT,
            }
        );
        assert!(matches!(config.source.format(), SourceFormat::Csv { .. }));

        let config = parse(",timeout=2m,reload=5m");
        assert_eq!(
            config.source.origin(),
            &Origin::Command {
                program: "/opt/ifnames.sh".into(),
                timeout: Duration::from_secs(120),
            }
        );
        assert_eq!(
            config.source.reload(),
            ReloadPolicy::Interval(Duration::from_secs(300))
        );
    }

    #[test]
    fn command_is_validated() {
        let error = |arg: &str| parse_enrich_arg(arg).unwrap_err().to_string();

        assert!(
            error("type=exact,source=a.csv,command=a.sh,key_column=k,fields=proto@name:n")
                .contains("mutually exclusive")
        );
        assert!(
            error("type=exact,key_column=k,fields=proto@name:n")
                .contains("Missing 'source' or 'command'")
        );
        assert!(
            error("type=exact,source=a.csv,timeout=5s,key_column=k,fields=proto@name:n")
                .contains("'timeout' is not valid for a file source")
        );
        assert!(
            error("type=exact,command=a.sh,reload=watch,key_column=k,fields=proto@name:n")
                .contains("cannot be watched")
        );
        assert!(
            error("type=prefix_lookup,command=a.sh,format=mmdb,fields=src_addr@asn:n")
                .contains("supports only CSV")
        );
        assert!(
            error("type=exact,command=a.sh,timeout=0s,key_column=k,fields=proto@name:n")
                .contains("must not be zero")
        );
        assert!(
            error("type=exact,command=a.sh,timeout=soon,key_column=k,fields=proto@name:n")
                .contains("Invalid timeout 'soon'")
        );
    }
}
