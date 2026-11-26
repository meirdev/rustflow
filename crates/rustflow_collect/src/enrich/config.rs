use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rustflow_core::common_flow::CommonFlow;
use serde::Deserialize;

use crate::enrich::{Error, Key, KeyType, ReloadPolicy, Result};
use crate::field;
use crate::schema::Column;

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
    Command { program: PathBuf, timeout: Duration },
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
    /// The columns read from the source, and the kind of their values.
    columns: Vec<(String, field::Kind)>,
}

impl SourceConfig {
    pub fn new(
        origin: Origin,
        format: SourceFormat,
        columns: Vec<(String, field::Kind)>,
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
        for (column, _) in &columns {
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
    pub fn columns(&self) -> &[(String, field::Kind)] {
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

/// A column that a lookup takes as a key: a field of the flow, or one of
/// its extra fields.
#[derive(Debug, Clone)]
pub struct LookupKey {
    column: Column,
    key_type: KeyType,
}

impl LookupKey {
    /// The key that is the column called `name` of `columns`.
    fn find(name: &str, columns: &[Column]) -> Result<Self> {
        let key = |column: &Column| {
            let key_type = KeyType::of(column.kind)?;
            Some(Self {
                column: column.clone(),
                key_type,
            })
        };
        let mut keys = columns.iter().filter_map(key);
        keys.find(|key| key.name() == name).ok_or_else(|| {
            let names: Vec<_> = columns.iter().filter_map(key).collect();
            let names: Vec<_> = names.iter().map(Self::name).collect();
            Error::Config(format!(
                "Unknown lookup key '{name}'. Valid keys: {}",
                names.join(", ")
            ))
        })
    }

    pub fn name(&self) -> &str {
        &self.column.name
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    pub fn extract(&self, flow: &CommonFlow) -> Option<Key> {
        Key::of(self.column.value(flow, &[])?)
    }
}

impl PartialEq for LookupKey {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for LookupKey {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMapping {
    /// The fields that together form the lookup key.
    pub keys: Vec<LookupKey>,
    pub source_column: String,
    pub output_field: String,
    /// The kind of the column's values, and so of the field's.
    pub kind: field::Kind,
    /// The field's protobuf number, when given one.
    pub number: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    pub source: SourceConfig,
    pub mappings: Vec<FieldMapping>,
}

/// An `[[enrich]]` of the configuration file, before its names are looked
/// up and its parts checked against each other.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichSpec {
    /// `prefix_lookup` or `exact`.
    #[serde(rename = "type")]
    pub kind: String,
    pub source: Option<PathBuf>,
    pub command: Option<PathBuf>,
    pub timeout: Option<String>,
    /// `csv` or `mmdb`; from the source's extension when left out.
    pub format: Option<String>,
    #[serde(default)]
    pub key_columns: Vec<String>,
    pub reload: Option<String>,
    #[serde(default, rename = "lookup")]
    pub lookups: Vec<LookupSpec>,
}

/// The fields one key gives.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupSpec {
    pub keys: Vec<String>,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// The column of the source.
    pub column: String,
    /// The name of the output field.
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// The field's protobuf number.
    pub number: Option<u32>,
}

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

impl EnrichSpec {
    fn mappings(&self, columns: &[Column]) -> Result<Vec<FieldMapping>> {
        let mut mappings = Vec::new();
        for LookupSpec { keys, fields } in &self.lookups {
            let names = keys.join("+");
            let keys = keys
                .iter()
                .map(|key| LookupKey::find(key, columns))
                .collect::<Result<Vec<LookupKey>>>()?;
            if keys.len() > MAX_KEYS {
                return Err(Error::Config(format!(
                    "At most {MAX_KEYS} lookup keys can be combined: '{names}'"
                )));
            }
            if fields.is_empty() {
                return Err(Error::Config(format!(
                    "The lookup of '{names}' has no fields"
                )));
            }
            for field in fields {
                let FieldSpec {
                    column,
                    name,
                    kind,
                    number,
                } = field;
                if column.is_empty() || name.is_empty() {
                    return Err(Error::Config(format!(
                        "A field of the lookup of '{names}' has no column or no name"
                    )));
                }
                let kind = match kind {
                    None => field::Kind::Text,
                    Some(kind) => kind.parse().map_err(|()| {
                        Error::Config(format!(
                            "'{kind}' of field '{name}' is not a type: string, unsigned, \
                             signed, float, boolean or timestamp"
                        ))
                    })?,
                };
                if CommonFlow::FIELD_NAMES.contains(&name.as_str()) {
                    return Err(Error::Config(format!(
                        "Output field '{name}' is the name of a flow field"
                    )));
                }
                mappings.push(FieldMapping {
                    keys: keys.clone(),
                    source_column: column.clone(),
                    output_field: name.clone(),
                    kind,
                    number: *number,
                });
            }
        }
        if mappings.is_empty() {
            return Err(Error::Config("An enrichment needs a lookup".into()));
        }
        Ok(mappings)
    }

    /// The enrichment, with its lookup keys found among `columns`, the
    /// flow's fields and the extra fields.
    pub fn resolve(&self, columns: &[Column]) -> Result<EnrichmentConfig> {
        let forbid = |given: bool, name: &str, context: &str| match given {
            true => Err(Error::Config(format!(
                "'{name}' is not valid for {context}"
            ))),
            false => Ok(()),
        };

        let kind: Kind = self.kind.parse()?;
        let origin = match (&self.source, &self.command) {
            (Some(path), None) => {
                forbid(self.timeout.is_some(), "timeout", "a file source")?;
                Origin::File(path.clone())
            }
            (None, Some(program)) => Origin::Command {
                program: program.clone(),
                timeout: match &self.timeout {
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
                    "An enrichment needs a 'source' or a 'command'".into(),
                ));
            }
        };

        let format: Format = match (&self.format, &origin) {
            (Some(format), _) => format.parse()?,
            (None, Origin::File(path)) => path
                .extension()
                .and_then(|extension| extension.to_str())
                .ok_or_else(|| {
                    Error::Config(
                        "Give format \"csv\" or \"mmdb\" when the source has no extension".into(),
                    )
                })?
                .parse()?,
            // An executable's extension says nothing about what it prints.
            (None, Origin::Command { .. }) => Format::Csv,
        };

        let mappings = self.mappings(columns)?;

        let key_types: Vec<KeyType> = mappings[0].keys.iter().map(|key| key.key_type()).collect();
        if mappings.iter().any(|m| {
            !m.keys
                .iter()
                .map(|key| key.key_type())
                .eq(key_types.iter().copied())
        }) {
            return Err(Error::Config(
                "All lookup groups of one source must use the same key types in the same order"
                    .into(),
            ));
        }

        if matches!(kind, Kind::Prefix) && key_types != [KeyType::Ip] {
            return Err(Error::Config(
                "prefix_lookup takes a single address field as key".into(),
            ));
        }

        let format = match (format, kind) {
            (Format::Csv, kind) => {
                let key_columns = self.key_columns.clone();
                if key_columns.is_empty() {
                    return Err(Error::Config("A CSV source needs 'key_columns'".into()));
                }
                if key_columns.len() != key_types.len() {
                    return Err(Error::Config(format!(
                        "'key_columns' lists {} columns for {} lookup keys",
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
                forbid(!self.key_columns.is_empty(), "key_columns", "MMDB")?;
                SourceFormat::Mmdb
            }
            (Format::Mmdb, Kind::Exact) => {
                return Err(Error::Config("MMDB supports only prefix_lookup".into()));
            }
        };

        let reload = match &self.reload {
            Some(reload) => reload.parse()?,
            None => ReloadPolicy::default(),
        };

        let mut columns: Vec<(String, field::Kind)> = Vec::new();
        for mapping in &mappings {
            let column = &mapping.source_column;
            match columns.iter().find(|(name, _)| name == column) {
                Some((_, kind)) if *kind != mapping.kind => {
                    return Err(Error::Config(format!(
                        "Source column '{column}' is given two types"
                    )));
                }
                Some(_) => {}
                None => columns.push((column.clone(), mapping.kind)),
            }
        }

        Ok(EnrichmentConfig {
            source: SourceConfig::new(origin, format, columns, reload)?,
            mappings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Field;
    use crate::schema::Schema;

    /// The flow's fields, as lookup keys are found among.
    fn columns() -> Vec<Column> {
        Schema::new(&[], &[]).unwrap().columns().to_vec()
    }

    fn names(mapping: &FieldMapping) -> Vec<&str> {
        mapping.keys.iter().map(|key| key.name()).collect()
    }

    fn field(column: &str, name: &str) -> FieldSpec {
        FieldSpec {
            column: column.into(),
            name: name.into(),
            kind: None,
            number: None,
        }
    }

    /// A lookup by `keys`, separated by `+`, of the column `name`.
    fn lookup(keys: &str, output: &str) -> LookupSpec {
        LookupSpec {
            keys: keys.split('+').map(String::from).collect(),
            fields: vec![field("name", output)],
        }
    }

    /// An enrichment from the CSV file `a.csv`, keyed by `key_columns`,
    /// separated by `+`.
    fn spec(kind: &str, key_columns: &str, lookups: Vec<LookupSpec>) -> EnrichSpec {
        EnrichSpec {
            kind: kind.into(),
            source: Some("a.csv".into()),
            key_columns: key_columns.split('+').map(String::from).collect(),
            lookups,
            ..EnrichSpec::default()
        }
    }

    fn error(spec: EnrichSpec) -> String {
        spec.resolve(&columns()).unwrap_err().to_string()
    }

    #[test]
    fn composite_keys_pair_columns_with_flow_fields() {
        let lookups = vec![
            lookup("sampler_address+in_if", "in_if_name"),
            lookup("sampler_address+out_if", "out_if_name"),
        ];
        let config = spec("exact", "exporter+ifindex", lookups)
            .resolve(&columns())
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

    fn typed(column: &str, name: &str, kind: Option<&str>, number: Option<u32>) -> FieldSpec {
        FieldSpec {
            kind: kind.map(String::from),
            number,
            ..field(column, name)
        }
    }

    fn by(key: &str, fields: Vec<FieldSpec>) -> LookupSpec {
        LookupSpec {
            keys: vec![key.into()],
            fields,
        }
    }

    #[test]
    fn an_output_can_have_a_type_and_a_field_number() {
        let fields = vec![
            typed("asn", "src_asn", Some("unsigned"), Some(1001)),
            typed("name", "src_name", None, None),
            typed("ok", "src_ok", Some("boolean"), Some(1003)),
        ];
        let config = spec("prefix_lookup", "net", vec![by("src_addr", fields)])
            .resolve(&columns())
            .unwrap();
        let outputs = config.mappings.iter();
        let outputs: Vec<_> = outputs
            .map(|m| (m.output_field.as_str(), m.kind, m.number))
            .collect();
        assert_eq!(
            outputs,
            [
                ("src_asn", field::Kind::U64, Some(1001)),
                ("src_name", field::Kind::Text, None),
                ("src_ok", field::Kind::Boolean, Some(1003)),
            ]
        );
        assert_eq!(
            config.source.columns()[0],
            ("asn".to_string(), field::Kind::U64)
        );

        let unknown = vec![typed("asn", "src_asn", Some("number"), None)];
        let unknown = spec("prefix_lookup", "net", vec![by("src_addr", unknown)]);
        assert!(error(unknown).contains("is not a type"));
        // One column read as two types.
        let lookups = vec![
            by(
                "src_addr",
                vec![typed("asn", "src_asn", Some("unsigned"), None)],
            ),
            by("dst_addr", vec![typed("asn", "dst_asn", None, None)]),
        ];
        assert!(error(spec("prefix_lookup", "net", lookups)).contains("is given two types"));
    }

    #[test]
    fn an_extra_field_can_be_a_lookup_key() {
        let extra = |name: &str, kind| Field {
            name: name.into(),
            kind,
            number: None,
        };
        let fields = [
            extra("vrf", field::Kind::U64),
            extra("tunnel", field::Kind::Address),
            extra("label", field::Kind::Octets),
        ];
        let schema = Schema::new(&fields, &[]).unwrap();
        let columns = schema.columns();
        let lookups = vec![lookup("sampler_address+vrf", "vrf_name")];
        let config = spec("exact", "exporter+id", lookups)
            .resolve(columns)
            .unwrap();
        assert_eq!(names(&config.mappings[0]), ["sampler_address", "vrf"]);

        let mut flow = CommonFlow::new(
            rustflow_core::common_flow::FlowType::Ipfix,
            0,
            [192, 0, 2, 1].into(),
            0,
        );
        let key = &config.mappings[0].keys[1];
        assert_eq!(key.extract(&flow), None);
        flow.extra = vec![Some(rustflow_core::value::Value::Unsigned32(7))].into();
        assert_eq!(key.extract(&flow), Some(Key::Number(7)));

        let prefix = |key| spec("prefix_lookup", "net", vec![lookup(key, "n")]).resolve(columns);
        assert!(prefix("tunnel").is_ok());
        assert!(prefix("vrf").is_err());
        assert!(prefix("other").is_err());
        // Octets are not keys.
        assert!(prefix("label").is_err());
    }

    #[test]
    fn composite_keys_are_validated() {
        let exact = |key_columns, lookups| error(spec("exact", key_columns, lookups));

        let lookups = vec![lookup("sampler_address+in_if", "n")];
        assert!(exact("exporter", lookups).contains("lists 1 columns for 2 lookup keys"));
        let lookups = vec![
            lookup("sampler_address+in_if", "n"),
            lookup("in_if+sampler_address", "m"),
        ];
        assert!(exact("a+b", lookups).contains("same key types in the same order"));
        let lookups = vec![lookup("src_addr+in_if", "n")];
        assert!(error(spec("prefix_lookup", "a+b", lookups)).contains("single address field"));
        let lookups = vec![lookup("in_if+out_if+src_port+dst_port+proto", "n")];
        assert!(exact("a+b+c+d+e", lookups).contains("At most 4 lookup keys"));
    }

    #[test]
    fn an_enrichment_needs_its_parts() {
        let base = || spec("exact", "k", vec![lookup("proto", "n")]);

        assert!(error(spec("exact", "k", Vec::new())).contains("needs a lookup"));
        assert!(error(spec("exact", "k", vec![by("proto", Vec::new())])).contains("has no fields"));
        let no_key_columns = EnrichSpec {
            key_columns: Vec::new(),
            ..base()
        };
        assert!(error(no_key_columns).contains("needs 'key_columns'"));
        let kind = EnrichSpec {
            kind: "fuzzy".into(),
            ..base()
        };
        assert!(error(kind).contains("Unknown type 'fuzzy'"));
    }

    #[test]
    fn an_output_field_cannot_be_a_flow_field() {
        for name in ["proto", "src_mac", "flow_type"] {
            let error = error(spec("exact", "k", vec![lookup("proto", name)]));
            assert!(error.contains("is the name of a flow field"), "{error}");
        }
    }

    /// An enrichment from the command `/opt/ifnames.sh`.
    fn command() -> EnrichSpec {
        EnrichSpec {
            source: None,
            command: Some("/opt/ifnames.sh".into()),
            ..spec("exact", "number", vec![lookup("proto", "n")])
        }
    }

    #[test]
    fn command_is_a_csv_source_with_a_timeout() {
        let config = command().resolve(&columns()).unwrap();
        assert_eq!(
            config.source.origin(),
            &Origin::Command {
                program: "/opt/ifnames.sh".into(),
                timeout: DEFAULT_TIMEOUT,
            }
        );
        assert!(matches!(config.source.format(), SourceFormat::Csv { .. }));

        let timed = EnrichSpec {
            timeout: Some("2m".into()),
            reload: Some("5m".into()),
            ..command()
        };
        let config = timed.resolve(&columns()).unwrap();
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
        let file = || spec("exact", "k", vec![lookup("proto", "n")]);
        let text = |value: &str| Some(value.to_string());

        let both = EnrichSpec {
            command: Some("a.sh".into()),
            ..file()
        };
        assert!(error(both).contains("mutually exclusive"));
        let neither = EnrichSpec {
            source: None,
            ..file()
        };
        assert!(error(neither).contains("needs a 'source' or a 'command'"));
        let timeout = EnrichSpec {
            timeout: text("5s"),
            ..file()
        };
        assert!(error(timeout).contains("'timeout' is not valid for a file source"));
        let watched = EnrichSpec {
            reload: text("watch"),
            ..command()
        };
        assert!(error(watched).contains("cannot be watched"));
        let mmdb = EnrichSpec {
            kind: "prefix_lookup".into(),
            format: text("mmdb"),
            key_columns: Vec::new(),
            lookups: vec![lookup("src_addr", "n")],
            ..command()
        };
        assert!(error(mmdb).contains("supports only CSV"));
        let zero = EnrichSpec {
            timeout: text("0s"),
            ..command()
        };
        assert!(error(zero).contains("must not be zero"));
        let soon = EnrichSpec {
            timeout: text("soon"),
            ..command()
        };
        assert!(error(soon).contains("Invalid timeout 'soon'"));
    }
}
