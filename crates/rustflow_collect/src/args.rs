use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::{Args as ClapArgs, ValueEnum};

use crate::enrich::{EnrichmentConfig, parse_enrich_arg};
use crate::sink::{MAX_PARTITION_LEVEL, OutputFormat, Serialization, SinkConfig};

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

    /// Serialization format for output (parquet is Snappy-compressed and
    /// requires `--format common` and `--output`)
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

    /// Directory partitioning of the output tree: 0 = flat, 1 = `%Y/%m/%d`,
    /// 2 = `%Y/%m/%d/%H`, 3 = `%Y/%m/%d/%H` plus a 5 minute bucket.
    /// Requires `--interval`.
    #[arg(
        short = 'l',
        long,
        default_value = "0",
        value_parser = clap::value_parser!(u8).range(0..=MAX_PARTITION_LEVEL as i64),
        requires = "interval"
    )]
    pub(crate) level: u8,

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

    /// Flow enrichment configuration
    /// Format: `type=prefix_lookup|exact,source=file.csv,key_column=col,
    /// fields=<key>@col:output|col2:output2;<key2>@col:output3[,
    /// reload=30s|watch]`. key_column names the CSV column holding the
    /// prefixes or keys; omit it for MMDB sources. An exact lookup can
    /// combine several keys with `+`, e.g. key_column=exporter+ifindex and
    /// fields=sampler_address+in_if@name:in_if_name
    #[arg(long = "enrich", value_parser = parse_enrich_arg)]
    pub(crate) enrich: Vec<EnrichmentConfig>,
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
    pub(crate) fn sink_config(&self) -> SinkConfig {
        SinkConfig {
            path: self.output.clone(),
            serialization: self.serialization,
            interval: self.interval,
            level: self.level,
            prefix: self.prefix.clone(),
            exec: self.exec.clone(),
        }
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
