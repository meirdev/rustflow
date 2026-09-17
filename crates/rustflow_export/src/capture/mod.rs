use anyhow::Result;

use crate::flow::FlowKey;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(target_os = "macos")]
mod bpf;
#[cfg(feature = "pcap")]
mod libpcap;
#[cfg(any(target_os = "linux", target_os = "macos", feature = "pcap"))]
mod packet;

pub trait Capture {
    fn next_packet(&mut self) -> Option<PacketInfo>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    /// The native backend of this platform
    Auto,
    /// AF_PACKET mmap ring (Linux only)
    AfPacket,
    /// BPF device, `/dev/bpfN` (macOS only)
    Bpf,
    /// libpcap / Npcap
    Pcap,
}

pub fn open(
    backend: Backend,
    interface: &str,
    promiscuous: bool,
    sampling_interval: u32,
) -> Result<Box<dyn Capture>> {
    match backend {
        Backend::Auto if cfg!(target_os = "linux") => {
            open_af_packet(interface, promiscuous, sampling_interval)
        }
        Backend::Auto if cfg!(target_os = "macos") => {
            open_bpf(interface, promiscuous, sampling_interval)
        }
        Backend::Auto | Backend::Pcap => open_pcap(interface, promiscuous, sampling_interval),
        Backend::AfPacket => open_af_packet(interface, promiscuous, sampling_interval),
        Backend::Bpf => open_bpf(interface, promiscuous, sampling_interval),
    }
}

#[cfg(target_os = "linux")]
fn open_af_packet(
    interface: &str,
    promiscuous: bool,
    sampling_interval: u32,
) -> Result<Box<dyn Capture>> {
    Ok(Box::new(af_packet::AfPacket::new(
        interface,
        promiscuous,
        sampling_interval,
    )?))
}

#[cfg(not(target_os = "linux"))]
fn open_af_packet(_: &str, _: bool, _: u32) -> Result<Box<dyn Capture>> {
    anyhow::bail!("The af-packet capture backend requires Linux; use --capture pcap")
}

#[cfg(target_os = "macos")]
fn open_bpf(
    interface: &str,
    promiscuous: bool,
    sampling_interval: u32,
) -> Result<Box<dyn Capture>> {
    Ok(Box::new(bpf::Bpf::new(
        interface,
        promiscuous,
        sampling_interval,
    )?))
}

#[cfg(not(target_os = "macos"))]
fn open_bpf(_: &str, _: bool, _: u32) -> Result<Box<dyn Capture>> {
    anyhow::bail!("The bpf capture backend requires macOS; use --capture pcap")
}

#[cfg(feature = "pcap")]
fn open_pcap(
    interface: &str,
    promiscuous: bool,
    sampling_interval: u32,
) -> Result<Box<dyn Capture>> {
    Ok(Box::new(libpcap::Libpcap::new(
        interface,
        promiscuous,
        sampling_interval,
    )?))
}

#[cfg(not(feature = "pcap"))]
fn open_pcap(_: &str, _: bool, _: u32) -> Result<Box<dyn Capture>> {
    anyhow::bail!("This build has no pcap support; rebuild with `--features pcap`")
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub flow_key: FlowKey,
    pub packet_size: u64,
    pub tcp_flags: u16,
}
