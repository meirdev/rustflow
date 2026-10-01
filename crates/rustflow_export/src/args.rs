use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::capture::Backend;
use crate::meter::Mode;
use crate::sampler::Sampling;

#[cfg(target_os = "macos")]
const DEFAULT_INTERFACE: &str = "lo0";
#[cfg(not(target_os = "macos"))]
const DEFAULT_INTERFACE: &str = "lo";

/// Arguments for the `export` subcommand.
#[derive(ClapArgs, Debug, Clone)]
pub struct ExportArgs {
    /// Network interface to capture from
    #[arg(short, long, default_value = DEFAULT_INTERFACE)]
    pub interface: String,

    /// Capture backend
    #[arg(long, value_enum, default_value = "auto")]
    pub capture: Backend,

    /// What to export
    #[arg(long, value_enum, default_value = "flow")]
    pub mode: Mode,

    /// Bytes of each sampled packet to export (`--mode packet`)
    #[arg(long, default_value = "128", value_parser = clap::value_parser!(u16).range(1..=1024))]
    pub clip_length: u16,

    /// Collector host: an IP address or a hostname
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub collector_host: String,

    /// Collector port
    #[arg(short = 'p', long, default_value = "4739")]
    pub collector_port: u16,

    /// Observation domain ID
    #[arg(long, default_value = "1")]
    pub observation_domain_id: u32,

    /// Active flow timeout in seconds
    #[arg(long, default_value = "60")]
    pub active_timeout: u64,

    /// Inactive flow timeout in seconds
    #[arg(long, default_value = "15")]
    pub inactive_timeout: u64,

    /// Template refresh rate in seconds
    #[arg(long, default_value = "300")]
    pub template_refresh_rate: u64,

    /// Sampling packet interval
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub sampling_packet_interval: u32,

    /// Enable promiscuous mode
    #[arg(long)]
    pub promiscuous: bool,
}

impl ExportArgs {
    pub(crate) fn sampling(&self) -> Sampling {
        Sampling::Count {
            interval: self.sampling_packet_interval,
        }
    }

    pub fn collector_addr(&self) -> Result<SocketAddr> {
        (self.collector_host.as_str(), self.collector_port)
            .to_socket_addrs()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Cannot resolve collector address {}:{}: {e}",
                    self.collector_host,
                    self.collector_port
                )
            })?
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Collector address {}:{} resolved to nothing",
                    self.collector_host,
                    self.collector_port
                )
            })
    }
}
