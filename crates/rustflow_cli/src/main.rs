//! The `rustflow` command line interface.
//!
//! Each subcommand is a thin wrapper over one of the tool crates, which own
//! both their argument definitions and their `run` entry points.

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustflow_collect::CollectArgs;
use rustflow_generate::GenerateArgs;

#[derive(Parser)]
#[command(name = "rustflow", version)]
#[command(about = "High-performance NetFlow, IPFIX and sFlow tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collect flows from the network or a pcap file and write them out
    Collect(Box<CollectArgs>),

    /// Generate synthetic IPFIX traffic for testing a collector
    Generate(Box<GenerateArgs>),

    /// Capture packets on an interface and export them as IPFIX (Linux only)
    #[cfg(target_os = "linux")]
    Export(Box<rustflow_export::ExportArgs>),

    /// Capture packets on an interface and export them as IPFIX (Linux only)
    #[cfg(not(target_os = "linux"))]
    #[command(disable_help_flag = true)]
    Export {
        /// Accepted so the platform error is reported instead of clap's
        /// "unrecognized subcommand".
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Cli::parse().command {
        Command::Collect(args) => {
            rustflow_collect::run(*args);
            Ok(())
        }
        Command::Generate(args) => {
            rustflow_generate::run(*args)?;
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Command::Export(args) => rustflow_export::run(*args),
        #[cfg(not(target_os = "linux"))]
        Command::Export { .. } => anyhow::bail!(
            "`rustflow export` requires Linux: packet capture uses AF_PACKET, \
             which this platform does not provide"
        ),
    }
}
