use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::builder::PossibleValue;
use clap::{Args as ClapArgs, ValueEnum};
use strum::VariantArray;

use crate::enrich::{EnrichmentConfig, parse_enrich_arg};
use crate::sink::{
    LEVEL_3_MINUTES, MAX_PARTITION_LEVEL, OutputFormat, Partitioning, Serialization, SinkConfig,
};

/// Arguments for the `collect` subcommand.
#[derive(ClapArgs)]
pub struct CollectArgs {
    /// Where flow data comes from: `netflow://[host]:port` or
    /// `sflow://[host]:port` listens on UDP, `netflow+pcap://capture.pcap`
    /// or `sflow+pcap://capture.pcap` reads a capture file. Repeat to
    /// combine several
    #[arg(short = 'I', long, value_name = "URL", required = true)]
    pub(crate) input: Vec<Input>,

    /// Socket receive buffer size in bytes
    #[arg(long, default_value = "4194304", value_name = "BYTES")]
    pub(crate) recv_buffer: usize,

    /// Output format: raw (original packet structure) or common (normalized
    /// flow)
    #[arg(short, long, value_enum, default_value = "raw")]
    pub(crate) format: OutputFormat,

    /// Serialization format for output; `parquet` requires `--format
    /// common` and `--output`, `discard` writes nothing
    #[arg(short, long, value_enum, default_value = "ndjson")]
    pub(crate) serialization: Serialization,

    /// Output path (stdout if not specified). Without `--interval` this is a
    /// single file; with `--interval` it is the root directory of the
    /// rotated output tree.
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    /// Start a new output file every interval (e.g. `10m`, `1h`).
    /// Requires `--output`, which then names a directory instead of a file.
    #[arg(
        short = 'i',
        long,
        value_name = "DURATION",
        requires = "output",
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) interval: Option<Duration>,

    /// Directory partitioning of the output tree: 1 = `%Y/%m/%d`,
    /// 2 = `%Y/%m/%d/%H`, 3 = `%Y/%m/%d/%H` plus a 5 minute bucket. Without
    /// it, files sit directly in the output directory. Requires `--interval`.
    #[arg(
        short = 'l',
        long,
        value_parser = clap::value_parser!(u8).range(1..=MAX_PARTITION_LEVEL as i64),
        requires = "interval"
    )]
    pub(crate) level: Option<u8>,

    /// Name partition directories the Hive way,
    /// `date=2026-08-27/hour=12/minute=00`, which query engines read as
    /// columns and prune by. Requires `--level`.
    #[arg(long, requires = "level")]
    pub(crate) hive: bool,

    /// File name prefix inside the output tree, e.g. `flows` produces
    /// `flows-20240102T150500Z.parquet`. Requires `--interval`.
    #[arg(long, default_value = "flows", requires = "interval")]
    pub(crate) prefix: String,

    /// Run a command after each rotated file is complete. `%f` is the file,
    /// `%p` its path below the output directory, `%t` the window start as
    /// in the file name, `%u` the same as Unix time; without a placeholder
    /// the file is appended. Requires `--interval`.
    #[arg(
        short = 'x',
        long = "exec",
        value_name = "COMMAND",
        requires = "interval"
    )]
    pub(crate) exec: Option<String>,

    /// Remove rotated files older than this age (e.g. `7d`, `30d`)
    #[arg(
        long,
        value_name = "DURATION",
        requires = "interval",
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) expire: Option<Duration>,

    /// Run a command after `--expire` removes a file, with the same
    /// placeholders as `-x`; the file is already gone when it runs.
    #[arg(long, value_name = "COMMAND", requires = "expire")]
    pub(crate) expire_exec: Option<String>,

    /// Host address for Prometheus metrics HTTP server
    #[arg(long, default_value = "0.0.0.0")]
    pub(crate) metrics_host: IpAddr,

    /// Port for Prometheus metrics HTTP server
    #[arg(long, default_value = "9090")]
    pub(crate) metrics_port: u16,

    /// Path to a CSV file with custom IE (Information Element) mappings
    #[arg(long)]
    pub(crate) ie_mapping: Option<PathBuf>,

    /// Template cache timeout, in seconds or with a unit (e.g. `20m`)
    #[arg(
        long,
        default_value = "600",
        value_name = "DURATION",
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) template_timeout: Duration,

    /// Flow enrichment configuration.
    ///
    /// Format: `type=prefix_lookup|exact,source=file.csv,key_column=col,
    /// fields=<key>@col:output|col2:output2;<key2>@col:output3[,
    /// reload=30s|watch]`. key_column names the CSV column holding the
    /// prefixes or keys; omit it for MMDB sources. An exact lookup can
    /// combine several keys with `+`, e.g. key_column=exporter+ifindex and
    /// fields=sampler_address+in_if@name:in_if_name
    #[arg(long = "enrich", value_parser = parse_enrich_arg)]
    pub(crate) enrich: Vec<EnrichmentConfig>,
}

impl ValueEnum for OutputFormat {
    fn value_variants<'a>() -> &'a [Self] {
        Self::VARIANTS
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(<&'static str>::from(*self)))
    }
}

impl ValueEnum for Serialization {
    fn value_variants<'a>() -> &'a [Self] {
        Self::VARIANTS
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(<&'static str>::from(*self)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FlowType {
    Netflow,
    Sflow,
}

impl FlowType {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Netflow => "NetFlow",
            Self::Sflow => "sFlow",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Input {
    /// A UDP socket to listen on.
    Listen {
        flow_type: FlowType,
        addr: SocketAddr,
    },
    /// A capture file to read.
    Pcap { flow_type: FlowType, path: PathBuf },
}

impl Input {
    pub(crate) fn flow_type(&self) -> FlowType {
        match self {
            Self::Listen { flow_type, .. } | Self::Pcap { flow_type, .. } => *flow_type,
        }
    }
}

impl FromStr for Input {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (scheme, rest) = value.split_once("://").ok_or(
            "expected netflow://[host]:port, sflow://[host]:port or <protocol>+pcap://file",
        )?;
        let (protocol, pcap) = match scheme.split_once('+') {
            None => (scheme, false),
            Some((protocol, "pcap")) => (protocol, true),
            Some((_, other)) => return Err(format!("unknown input kind '{other}', expected pcap")),
        };
        let flow_type = match protocol {
            "netflow" => FlowType::Netflow,
            "sflow" => FlowType::Sflow,
            other => {
                return Err(format!(
                    "unknown protocol '{other}', expected netflow or sflow"
                ));
            }
        };

        if pcap {
            if rest.is_empty() {
                return Err("missing file path".into());
            }
            return Ok(Self::Pcap {
                flow_type,
                path: PathBuf::from(rest),
            });
        }

        let (host, port) = rest.rsplit_once(':').ok_or("missing port")?;
        let port = port.parse().map_err(|_| format!("invalid port '{port}'"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let host = if host.is_empty() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            host.parse()
                .map_err(|_| format!("invalid host address '{host}'"))?
        };
        Ok(Self::Listen {
            flow_type,
            addr: SocketAddr::new(host, port),
        })
    }
}

impl CollectArgs {
    pub(crate) fn sink_config(&self) -> Result<SinkConfig> {
        let serialization = self.serialization;
        if self.format == OutputFormat::Raw && !serialization.takes_raw() {
            bail!("--serialization {serialization} requires --format common");
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

    fn listen(flow_type: FlowType, addr: &str) -> Input {
        Input::Listen {
            flow_type,
            addr: addr.parse().unwrap(),
        }
    }

    fn pcap(flow_type: FlowType, path: &str) -> Input {
        Input::Pcap {
            flow_type,
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn input_urls_name_the_protocol_and_the_socket_or_file() {
        let args = parse(&[
            "--input",
            "netflow://:9995",
            "--input",
            "sflow://[::1]:6343",
            "--input",
            "netflow://192.0.2.1:2055",
            "--input",
            "sflow+pcap:///var/tmp/flows.pcap",
            "--input",
            "netflow+pcap://flows.pcap",
        ])
        .unwrap();
        assert_eq!(
            args.input,
            [
                listen(FlowType::Netflow, "0.0.0.0:9995"),
                listen(FlowType::Sflow, "[::1]:6343"),
                listen(FlowType::Netflow, "192.0.2.1:2055"),
                pcap(FlowType::Sflow, "/var/tmp/flows.pcap"),
                pcap(FlowType::Netflow, "flows.pcap"),
            ]
        );
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
            parse(&args)
        };
        assert!(parse_with(&["--hive"]).is_err());
        assert_eq!(parse_with(&["--hive", "-l", "1"]).unwrap().level, Some(1));
        assert_eq!(parse_with(&[]).unwrap().level, None);
    }

    #[test]
    fn output_flags_are_checked_against_each_other() {
        let error = |args: &[&str]| {
            let base = ["-I", "netflow://:9995", "-o", "out"];
            let args: Vec<_> = base.iter().chain(args).copied().collect();
            parse(&args)
                .unwrap()
                .sink_config()
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
    fn an_input_is_required_and_malformed_urls_are_rejected() {
        assert!(parse(&[]).is_err());
        assert_eq!(
            parse(&["-I", "sflow://:6343"]).unwrap().input,
            [listen(FlowType::Sflow, "0.0.0.0:6343")]
        );
        for url in [
            "flows.pcap",
            "netflow",
            "netflow+pcap://",
            "netflow+file://flows.pcap",
            "http://:1",
            "netflow://:x",
            "netflow://router:1",
            "netflow://",
        ] {
            assert!(parse(&["--input", url]).is_err(), "{url}");
        }
    }
}
