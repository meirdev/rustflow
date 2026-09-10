use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::{Error, KeyType, ReloadPolicy, Result};

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
pub struct EnrichmentConfig {
    source: PathBuf,
    format: SourceFormat,
    reload: ReloadPolicy,
    columns: Vec<String>,
}

impl EnrichmentConfig {
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

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ip" => Ok(Self::Ip),
            "number" => Ok(Self::Number),
            "text" => Ok(Self::Text),
            other => Err(Error::Config(format!("Unknown key_type '{other}'"))),
        }
    }
}

const PARAMETERS: &[&str] = &[
    "type",
    "format",
    "source",
    "prefix_column",
    "key_column",
    "key_type",
    "columns",
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
    let format = match (format, kind) {
        (Format::Csv, Kind::Prefix) => {
            forbid(&["key_column", "key_type"], "CSV prefix_lookup")?;
            SourceFormat::Csv(CsvLookup::Prefix {
                prefix_column: required("prefix_column")?.into(),
            })
        }
        (Format::Csv, Kind::Exact) => {
            forbid(&["prefix_column"], "CSV exact lookup")?;
            SourceFormat::Csv(CsvLookup::Exact {
                key_column: required("key_column")?.into(),
                key_type: required("key_type")?.parse()?,
            })
        }
        (Format::Mmdb, Kind::Prefix) => {
            forbid(&["prefix_column", "key_column", "key_type"], "MMDB")?;
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

    EnrichmentConfig::new(
        source,
        format,
        required("columns")?
            .split('|')
            .map(|s| s.trim().to_owned())
            .collect(),
        reload,
    )
}
