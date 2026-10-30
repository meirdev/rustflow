use std::io::Write;

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

    /// Capture packets on an interface and export them as IPFIX
    Export(Box<rustflow_export::ExportArgs>),
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "{} {style}{:<5}{style:#} {}",
                buf.timestamp(),
                record.level(),
                record.args()
            )
        })
        .init();

    match Cli::parse().command {
        Command::Collect(args) => rustflow_collect::run(*args),
        Command::Generate(args) => rustflow_generate::run(*args),
        Command::Export(args) => rustflow_export::run(*args),
    }
}
