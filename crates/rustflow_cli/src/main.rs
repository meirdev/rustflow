//! The `rustflow` command line interface.
//!
//! Each subcommand is a thin wrapper over one of the tool crates, which own
//! both their argument definitions and their `run` entry points.

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustflow_collect::CollectArgs;
use rustflow_generate::GenerateArgs;
use rustflow_relay::RelayArgs;

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

    /// Relay UDP flow datagrams to another collector
    Relay(Box<RelayArgs>),

    /// Capture packets on an interface and export them as IPFIX
    Export(Box<rustflow_export::ExportArgs>),
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
        Command::Relay(args) => rustflow_relay::run(*args),
        Command::Export(args) => rustflow_export::run(*args),
    }
}
