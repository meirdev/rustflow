use std::path::PathBuf;
use std::time::Duration;

use clap::{Args as ClapArgs, ValueEnum};

use crate::enrich::{EnrichmentConfig, parse_enrich_arg};
use crate::sink::{MAX_PARTITION_LEVEL, OutputFormat, Serialization, SinkConfig};

/// Arguments for the `collect` subcommand.
#[derive(ClapArgs)]
pub struct CollectArgs {
    /// Flow protocol type to collect
    #[arg(short = 't', long, value_enum)]
    pub(crate) flow_type: FlowType,

    /// Path to a pcap file to read instead of listening on a socket
    #[arg(long, conflicts_with_all = ["host", "port"])]
    pub(crate) pcap: Option<PathBuf>,

    /// Host address to bind the UDP socket
    #[arg(short = 'H', long, default_value = "0.0.0.0", requires = "port")]
    pub(crate) host: String,

    /// UDP port to listen for flow data
    #[arg(short, long, conflicts_with = "pcap")]
    pub(crate) port: Option<u16>,

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
    /// `%t` the window start as in the file name, `%u` the same as Unix
    /// time; without a placeholder the file is appended. Requires
    /// `--interval`.
    #[arg(
        short = 'x',
        long = "exec",
        value_name = "COMMAND",
        requires = "interval"
    )]
    pub(crate) exec: Option<String>,

    /// Host address for Prometheus metrics HTTP server
    #[arg(long, default_value = "0.0.0.0")]
    pub(crate) metrics_host: String,

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
    /// Format: type=prefix_lookup|exact,source=file.csv,key_column=col,
    /// fields=<key>@col:output|col2:output2;<key2>@col:output3[,
    /// reload=30s|watch]. key_column names the CSV column holding the
    /// prefixes or keys; omit it for MMDB sources
    #[arg(long = "enrich", value_parser = parse_enrich_arg)]
    pub(crate) enrich: Vec<EnrichmentConfig>,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum FlowType {
    Netflow,
    Sflow,
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
