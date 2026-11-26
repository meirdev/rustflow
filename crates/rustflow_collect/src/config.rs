//! The collector's settings: the configuration file, and the command line
//! over it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer};

use crate::args::{CollectArgs, Input};
use crate::enrich::config::EnrichSpec;
use crate::extra_field::ExtraFieldSpec;
use crate::ie_mapping::Element;
use crate::sink::{
    LEVEL_3_MINUTES, MAX_PARTITION_LEVEL, OutputFormat, Partitioning, Serialization, SinkConfig,
};

const DEFAULT_RECV_BUFFER: usize = 4 * 1024 * 1024;
const DEFAULT_TEMPLATE_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_PREFIX: &str = "flows";
const DEFAULT_METRICS_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const DEFAULT_METRICS_PORT: u16 = 9090;

/// A duration as the flags take it: seconds, or a number with a unit.
fn duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Duration>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Text {
        Seconds(u64),
        WithUnit(String),
    }

    Ok(Some(match Text::deserialize(deserializer)? {
        Text::Seconds(seconds) => Duration::from_secs(seconds),
        Text::WithUnit(text) => {
            duration_str::parse(text.trim()).map_err(serde::de::Error::custom)?
        }
    }))
}

/// The configuration file. A key that is not one of these is an error.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    input: Vec<InputEntry>,
    recv_buffer: Option<usize>,
    #[serde(default, deserialize_with = "duration")]
    template_timeout: Option<Duration>,
    ie_mapping: Option<PathBuf>,
    #[serde(default)]
    output: Output,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default, rename = "element")]
    elements: Vec<Element>,
    #[serde(default, rename = "extra_field")]
    extra_fields: Vec<ExtraFieldSpec>,
    #[serde(default)]
    enrich: Vec<EnrichSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputEntry {
    url: Input,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    format: Option<OutputFormat>,
    serialization: Option<Serialization>,
    path: Option<PathBuf>,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    rotation: Rotation,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotation {
    #[serde(default, deserialize_with = "duration")]
    interval: Option<Duration>,
    level: Option<u8>,
    hive: Option<bool>,
    prefix: Option<String>,
    exec: Option<String>,
    #[serde(default, deserialize_with = "duration")]
    expire: Option<Duration>,
    expire_exec: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metrics {
    host: Option<IpAddr>,
    port: Option<u16>,
}

impl ConfigFile {
    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read the configuration {}", path.display()))?;
        let mut config: Self = toml::from_str(&text)
            .with_context(|| format!("Invalid configuration {}", path.display()))?;
        config.rebase(path.parent().unwrap_or(Path::new("")));
        Ok(config)
    }

    /// A relative path in the file is relative to the file, so that a
    /// configuration and what it names can be moved together.
    fn rebase(&mut self, directory: &Path) {
        let rebase = |path: &mut PathBuf| *path = directory.join(&*path);
        for input in &mut self.input {
            if let Input::Pcap { path, .. } = &mut input.url {
                rebase(path);
            }
        }
        self.ie_mapping.iter_mut().for_each(rebase);
        self.output.path.iter_mut().for_each(rebase);
        for enrich in &mut self.enrich {
            enrich.source.iter_mut().for_each(rebase);
            enrich.command.iter_mut().for_each(rebase);
        }
    }
}

/// What the collector runs with.
#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) inputs: Vec<Input>,
    pub(crate) recv_buffer: usize,
    pub(crate) format: OutputFormat,
    pub(crate) serialization: Serialization,
    pub(crate) output: Option<PathBuf>,
    pub(crate) interval: Option<Duration>,
    pub(crate) level: Option<u8>,
    pub(crate) hive: bool,
    pub(crate) prefix: String,
    pub(crate) exec: Option<String>,
    pub(crate) expire: Option<Duration>,
    pub(crate) expire_exec: Option<String>,
    pub(crate) metrics_host: IpAddr,
    pub(crate) metrics_port: u16,
    pub(crate) ie_mapping: Option<PathBuf>,
    pub(crate) elements: Vec<Element>,
    pub(crate) extra_fields: Vec<ExtraFieldSpec>,
    pub(crate) fields: Vec<String>,
    pub(crate) template_timeout: Duration,
    pub(crate) enrich: Vec<EnrichSpec>,
}

/// The flag's list if it gave one, or else the file's.
fn or<T>(flag: Vec<T>, file: Vec<T>) -> Vec<T> {
    if flag.is_empty() { file } else { flag }
}

impl CollectArgs {
    /// The settings of the configuration file, if one is given, with the
    /// flags over them: a flag replaces the file's setting.
    pub(crate) fn settings(self) -> Result<Settings> {
        let file = match &self.config {
            Some(path) => ConfigFile::load(path)?,
            None => ConfigFile::default(),
        };
        let ConfigFile {
            input,
            recv_buffer,
            template_timeout,
            ie_mapping,
            output,
            metrics,
            elements,
            extra_fields,
            enrich,
        } = file;
        let rotation = output.rotation;

        let settings = Settings {
            inputs: or(
                self.input,
                input.into_iter().map(|input| input.url).collect(),
            ),
            recv_buffer: (self.recv_buffer.or(recv_buffer)).unwrap_or(DEFAULT_RECV_BUFFER),
            format: self.format.or(output.format).unwrap_or(OutputFormat::Raw),
            serialization: (self.serialization.or(output.serialization))
                .unwrap_or(Serialization::Ndjson),
            output: self.output.or(output.path),
            interval: self.interval.or(rotation.interval),
            level: self.level.or(rotation.level),
            hive: self.hive || rotation.hive.unwrap_or(false),
            prefix: (self.prefix.clone().or(rotation.prefix.clone()))
                .unwrap_or_else(|| DEFAULT_PREFIX.into()),
            exec: self.exec.or(rotation.exec),
            expire: self.expire.or(rotation.expire),
            expire_exec: self.expire_exec.or(rotation.expire_exec),
            metrics_host: (self.metrics_host.or(metrics.host)).unwrap_or(DEFAULT_METRICS_HOST),
            metrics_port: (self.metrics_port.or(metrics.port)).unwrap_or(DEFAULT_METRICS_PORT),
            ie_mapping: self.ie_mapping.or(ie_mapping),
            elements,
            extra_fields,
            fields: or(self.fields, output.fields),
            template_timeout: (self.template_timeout.or(template_timeout))
                .unwrap_or(DEFAULT_TEMPLATE_TIMEOUT),
            enrich,
        };
        settings.check(self.prefix.or(rotation.prefix).is_some())?;
        Ok(settings)
    }
}

impl Settings {
    /// The settings that need another one. `prefix_given` is whether the
    /// prefix is not just its default.
    fn check(&self, prefix_given: bool) -> Result<()> {
        if self.inputs.is_empty() {
            bail!("No input: give --input, or an [[input]] in the configuration file");
        }
        let needs = |given: bool, name: &str, other: &str, present: bool| {
            if given && !present {
                bail!("{name} requires {other}");
            }
            Ok(())
        };
        let interval = self.interval.is_some();
        needs(interval, "--interval", "--output", self.output.is_some())?;
        needs(self.level.is_some(), "--level", "--interval", interval)?;
        needs(self.hive, "--hive", "--level", self.level.is_some())?;
        needs(prefix_given, "--prefix", "--interval", interval)?;
        needs(self.exec.is_some(), "--exec", "--interval", interval)?;
        needs(self.expire.is_some(), "--expire", "--interval", interval)?;
        let expire = self.expire.is_some();
        needs(
            self.expire_exec.is_some(),
            "--expire-exec",
            "--expire",
            expire,
        )?;
        if let Some(level) = self.level
            && !(1..=MAX_PARTITION_LEVEL).contains(&level)
        {
            bail!("--level must be between 1 and {MAX_PARTITION_LEVEL}");
        }
        Ok(())
    }

    pub(crate) fn sink_config(&self) -> Result<SinkConfig> {
        let serialization = self.serialization;
        if self.format == OutputFormat::Raw && !serialization.takes_raw() {
            bail!("--serialization {serialization} requires --format common");
        }
        if self.format == OutputFormat::Raw && !self.extra_fields.is_empty() {
            bail!("An extra field requires the common format");
        }
        if self.format == OutputFormat::Raw && !self.fields.is_empty() {
            bail!("--fields requires --format common");
        }
        if let Some(interval) = self.interval {
            check_interval(interval, self.level)?;
        }
        if let (Some(expire), Some(interval)) = (self.expire, self.interval)
            && expire < interval
        {
            bail!("--expire must be at least as long as --interval");
        }

        Ok(SinkConfig {
            path: self.output.clone(),
            serialization: self.serialization,
            interval: self.interval,
            level: self.level.unwrap_or(0),
            partitioning: if self.hive {
                Partitioning::Hive
            } else {
                Partitioning::Plain
            },
            prefix: self.prefix.clone(),
            exec: self.exec.clone(),
            expire: self.expire,
            expire_exec: self.expire_exec.clone(),
        })
    }
}

/// A window must be whole seconds and sit inside one partition directory,
/// so the directory means what it says: every file under hour 13 holds
/// flows received in hour 13. That takes an interval dividing the
/// directory's period.
fn check_interval(interval: Duration, level: Option<u8>) -> Result<()> {
    if interval.is_zero() || interval.subsec_nanos() != 0 {
        bail!("--interval must be whole seconds");
    }
    let Some(level) = level else {
        return Ok(());
    };
    let (period, name) = match level {
        1 => (86400, "a day"),
        2 => (3600, "an hour"),
        _ => (u64::from(LEVEL_3_MINUTES) * 60, "5 minutes"),
    };
    if !period.is_multiple_of(interval.as_secs()) {
        bail!(
            "--interval must divide {name} at --level {level}, e.g. {}",
            examples(period)
        );
    }
    Ok(())
}

/// A few intervals dividing `period`, largest first.
fn examples(period: u64) -> String {
    [3600, 1800, 600, 300, 60, 30, 10]
        .into_iter()
        .filter(|candidate| period.is_multiple_of(*candidate) && *candidate <= period)
        .take(3)
        .map(|secs| {
            if secs >= 3600 {
                format!("{}h", secs / 3600)
            } else if secs >= 60 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: CollectArgs,
    }

    fn parse(args: &[&str]) -> Result<CollectArgs, clap::Error> {
        Cli::try_parse_from(["rustflow"].into_iter().chain(args.iter().copied()))
            .map(|cli| cli.args)
    }

    fn settings(args: &[&str]) -> Result<Settings> {
        parse(args)?.settings()
    }

    /// The settings of `args` and a configuration file holding `config`.
    fn with_file(config: &str, args: &[&str]) -> Result<Settings> {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(config.as_bytes()).unwrap();
        let path = file.path().to_str().unwrap();
        let args: Vec<_> = ["--config", path].iter().chain(args).copied().collect();
        settings(&args)
    }

    #[test]
    fn intervals_must_fit_their_partition() {
        let s = Duration::from_secs;
        let ok = |interval, level| check_interval(interval, level).is_ok();

        assert!(ok(s(7 * 60), None));
        assert!(ok(s(7 * 3600), None));
        assert!(ok(s(8 * 3600), Some(1)));
        assert!(!ok(s(7 * 3600), Some(1)));
        assert!(ok(s(5 * 60), Some(2)));
        assert!(ok(s(3600), Some(2)));
        assert!(!ok(s(7 * 60), Some(2)));
        assert!(!ok(s(2 * 3600), Some(2)));
        assert!(ok(s(60), Some(3)));
        assert!(ok(s(300), Some(3)));
        assert!(!ok(s(120), Some(3)));
        assert!(!ok(s(600), Some(3)));
        assert!(!ok(Duration::from_millis(1500), None));
        assert!(!ok(Duration::ZERO, None));

        let error = check_interval(s(7 * 60), Some(2)).unwrap_err().to_string();
        assert_eq!(
            error,
            "--interval must divide an hour at --level 2, e.g. 1h, 30m, 10m"
        );
        let error = check_interval(s(600), Some(3)).unwrap_err().to_string();
        assert_eq!(
            error,
            "--interval must divide 5 minutes at --level 3, e.g. 5m, 1m, 30s"
        );
    }

    #[test]
    fn hive_needs_a_partition_level() {
        let base = ["-I", "netflow://:9995", "-o", "out", "-i", "1m"];
        let parse_with = |extra: &[&str]| {
            let args: Vec<_> = base.iter().chain(extra).copied().collect();
            settings(&args)
        };
        assert!(parse_with(&["--hive"]).is_err());
        assert_eq!(parse_with(&["--hive", "-l", "1"]).unwrap().level, Some(1));
        assert_eq!(parse_with(&[]).unwrap().level, None);
        assert!(parse_with(&["-l", "4"]).is_err());
    }

    #[test]
    fn output_flags_are_checked_against_each_other() {
        let error = |args: &[&str]| {
            let base = ["-I", "netflow://:9995", "-o", "out"];
            let args: Vec<_> = base.iter().chain(args).copied().collect();
            settings(&args)
                .and_then(|settings| settings.sink_config())
                .err()
                .map(|e| e.to_string())
        };

        assert_eq!(
            error(&["-s", "parquet"]).as_deref(),
            Some("--serialization parquet requires --format common")
        );
        assert_eq!(error(&["-s", "ndjson"]), None);
        assert_eq!(
            error(&["-i", "1m", "--expire", "30s"]).as_deref(),
            Some("--expire must be at least as long as --interval")
        );
        assert_eq!(
            error(&["-i", "1m", "-l", "3", "--hive", "--expire", "1h"]),
            None
        );
    }

    #[test]
    fn flags_need_the_flags_they_depend_on() {
        let error = |args: &[&str]| {
            let args: Vec<_> = ["-I", "netflow://:9995"]
                .iter()
                .chain(args)
                .copied()
                .collect();
            settings(&args).err().map(|e| e.to_string())
        };

        assert_eq!(
            settings(&[]).unwrap_err().to_string().split(':').next(),
            Some("No input")
        );
        assert_eq!(error(&[]), None);
        assert_eq!(
            error(&["-i", "1m"]).as_deref(),
            Some("--interval requires --output")
        );
        assert_eq!(
            error(&["-o", "out", "-l", "1"]).as_deref(),
            Some("--level requires --interval")
        );
        assert_eq!(
            error(&["-o", "out", "--prefix", "x"]).as_deref(),
            Some("--prefix requires --interval")
        );
        assert_eq!(
            error(&["-o", "out", "-i", "1m", "--expire-exec", "x"]).as_deref(),
            Some("--expire-exec requires --expire")
        );
    }

    const CONFIG: &str = r#"
        recv_buffer = 1024
        template_timeout = "20m"
        ie_mapping = "elements.csv"

        [[input]]
        url = "netflow://:9995"

        [[input]]
        url = "sflow+pcap://capture.pcap"

        [output]
        format = "common"
        serialization = "parquet"
        path = "flows"
        fields = ["src_addr", "vrf"]

        [output.rotation]
        interval = 300
        level = 2
        hive = true
        expire = "30d"

        [metrics]
        port = 9100

        [[element]]
        enterprise = 9
        id = 12235
        name = "applicationName"
        type = "string"

        [[extra_field]]
        name = "vrf"
        element = "ingressVRFID"
        number = 1000

        [[enrich]]
        type = "exact"
        source = "vrfs.csv"
        key_columns = ["exporter", "id"]
        reload = "10m"

        [[enrich.lookup]]
        keys = ["sampler_address", "vrf"]
        fields = [{ column = "name", name = "vrf_name", type = "string", number = 1001 }]
    "#;

    #[test]
    fn a_configuration_file_gives_the_settings() {
        let settings = with_file(CONFIG, &[]).unwrap();
        let directory = std::env::temp_dir();

        assert_eq!(settings.inputs.len(), 2);
        assert!(matches!(
            &settings.inputs[1],
            Input::Pcap { path, .. } if path.is_absolute() && path.ends_with("capture.pcap")
        ));
        assert_eq!(settings.recv_buffer, 1024);
        assert_eq!(settings.template_timeout, Duration::from_secs(1200));
        assert_eq!(settings.format, OutputFormat::Common);
        assert_eq!(settings.serialization, Serialization::Parquet);
        assert_eq!(settings.interval, Some(Duration::from_secs(300)));
        assert_eq!(settings.expire, Some(Duration::from_secs(30 * 86400)));
        assert_eq!((settings.level, settings.hive), (Some(2), true));
        assert_eq!(settings.prefix, "flows");
        assert_eq!(settings.metrics_port, 9100);
        assert_eq!(settings.metrics_host, DEFAULT_METRICS_HOST);
        assert_eq!(settings.fields, ["src_addr", "vrf"]);
        assert_eq!(settings.elements.len(), 1);
        assert_eq!(settings.extra_fields.len(), 1);
        // Paths are relative to the file.
        let beside = |name: &str| Some(std::fs::canonicalize(&directory).unwrap().join(name));
        let canonical = |path: &Option<PathBuf>| {
            let path = path.as_ref()?;
            Some(
                std::fs::canonicalize(path.parent()?)
                    .ok()?
                    .join(path.file_name()?),
            )
        };
        assert_eq!(canonical(&settings.output), beside("flows"));
        assert_eq!(canonical(&settings.ie_mapping), beside("elements.csv"));
        let enrich = &settings.enrich[0];
        assert_eq!(canonical(&enrich.source), beside("vrfs.csv"));
        assert_eq!(enrich.key_columns, ["exporter", "id"]);
        assert_eq!(enrich.lookups[0].keys, ["sampler_address", "vrf"]);
        assert_eq!(enrich.lookups[0].fields[0].number, Some(1001));
        settings.sink_config().unwrap();
    }

    #[test]
    fn a_flag_replaces_the_setting_of_the_file() {
        let settings = with_file(
            CONFIG,
            &[
                "-I",
                "sflow://:6343",
                "-s",
                "csv",
                "--metrics-port",
                "1",
                "--fields",
                "bytes",
            ],
        )
        .unwrap();

        assert_eq!(settings.inputs.len(), 1);
        assert_eq!(settings.serialization, Serialization::Csv);
        assert_eq!(settings.format, OutputFormat::Common);
        assert_eq!(settings.metrics_port, 1);
        assert_eq!(settings.fields, ["bytes"]);
        assert_eq!(settings.extra_fields.len(), 1);
    }

    #[test]
    fn an_unknown_key_or_a_bad_value_is_an_error() {
        let error = |config: &str| format!("{:#}", with_file(config, &[]).unwrap_err());

        assert!(error("serialisation = \"csv\"").contains("unknown field `serialisation`"));
        assert!(error("[output]\nrotate = 1").contains("unknown field `rotate`"));
        assert!(error("[output]\nserialization = \"xml\"").contains("xml"));
        assert!(error("[[input]]\nurl = \"http://:1\"").contains("unknown protocol"));
        assert!(error("template_timeout = \"soon\"").contains("template_timeout"));
        assert!(error("[[enrich]]\ntype = \"exact\"\nkeys = []").contains("unknown field `keys`"));
        assert!(settings(&["--config", "/no/such/rustflow.toml"]).is_err());
    }
}
