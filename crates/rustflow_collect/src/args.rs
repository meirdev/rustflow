use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::builder::PossibleValue;
use clap::{Args as ClapArgs, ValueEnum};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use strum::VariantArray;

use crate::sink::{OutputFormat, Serialization};

/// Arguments for the `collect` subcommand. Each can also be set in the
/// configuration file, and wins over it when given.
#[derive(ClapArgs)]
pub struct CollectArgs {
    /// A TOML configuration file, which can set what the flags set, and
    /// also extra fields, enrichment and custom elements; see
    /// docs/configuration.md
    #[arg(short, long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Where flow data comes from: `netflow://[host]:port` or
    /// `sflow://[host]:port` listens on UDP, `netflow+pcap://capture.pcap`
    /// or `sflow+pcap://capture.pcap` reads a capture file. Repeat to
    /// combine several
    #[arg(short = 'I', long, value_name = "URL")]
    pub(crate) input: Vec<Input>,

    /// Socket receive buffer size in bytes [default: 4194304]
    #[arg(long, value_name = "BYTES")]
    pub(crate) recv_buffer: Option<usize>,

    /// Output format: raw (original packet structure) or common (normalized
    /// flow) [default: raw]
    #[arg(short, long, value_enum)]
    pub(crate) format: Option<OutputFormat>,

    /// Serialization format for output; `parquet` requires `--format
    /// common` and `--output`, `discard` writes nothing [default: ndjson]
    #[arg(short, long, value_enum)]
    pub(crate) serialization: Option<Serialization>,

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
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) interval: Option<Duration>,

    /// Directory partitioning of the output tree: 1 = `%Y/%m/%d`,
    /// 2 = `%Y/%m/%d/%H`, 3 = `%Y/%m/%d/%H` plus a 5 minute bucket. Without
    /// it, files sit directly in the output directory. Requires `--interval`.
    #[arg(short = 'l', long)]
    pub(crate) level: Option<u8>,

    /// Name partition directories the Hive way,
    /// `date=2026-08-27/hour=12/minute=00`, which query engines read as
    /// columns and prune by. Requires `--level`.
    #[arg(long)]
    pub(crate) hive: bool,

    /// File name prefix inside the output tree, e.g. `flows` produces
    /// `flows-20240102T150500Z.parquet`. Requires `--interval`
    /// [default: flows]
    #[arg(long)]
    pub(crate) prefix: Option<String>,

    /// Run a command after each rotated file is complete. `%f` is the file,
    /// `%p` its path below the output directory, `%t` the window start as
    /// in the file name, `%u` the same as Unix time; without a placeholder
    /// the file is appended. Requires `--interval`.
    #[arg(short = 'x', long = "exec", value_name = "COMMAND")]
    pub(crate) exec: Option<String>,

    /// Remove rotated files older than this age (e.g. `7d`, `30d`).
    /// Requires `--interval`
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) expire: Option<Duration>,

    /// Run a command after `--expire` removes a file, with the same
    /// placeholders as `-x`; the file is already gone when it runs.
    #[arg(long, value_name = "COMMAND")]
    pub(crate) expire_exec: Option<String>,

    /// Host address for Prometheus metrics HTTP server [default: 0.0.0.0]
    #[arg(long)]
    pub(crate) metrics_host: Option<IpAddr>,

    /// Port for Prometheus metrics HTTP server [default: 9090]
    #[arg(long)]
    pub(crate) metrics_port: Option<u16>,

    /// Path to a CSV file with custom IE (Information Element) mappings
    #[arg(long)]
    pub(crate) ie_mapping: Option<PathBuf>,

    /// Write only these columns, by name: common flow fields, extra
    /// fields and enrichment outputs, in this order
    #[arg(long, value_name = "NAME,...", value_delimiter = ',')]
    pub(crate) fields: Vec<String>,

    /// Template cache timeout, in seconds or with a unit (e.g. `20m`)
    /// [default: 600]
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = |value: &str| duration_str::parse(value.trim())
    )]
    pub(crate) template_timeout: Option<Duration>,
}

/// In the configuration file, by the name the flag takes.
impl<'de> Deserialize<'de> for OutputFormat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        ValueEnum::from_str(&name, false).map_err(D::Error::custom)
    }
}

/// In the configuration file, by the name the flag takes.
impl<'de> Deserialize<'de> for Serialization {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        ValueEnum::from_str(&name, false).map_err(D::Error::custom)
    }
}

/// In the configuration file, as the URL `--input` takes.
impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
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
    fn malformed_urls_are_rejected() {
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
