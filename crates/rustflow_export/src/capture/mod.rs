use anyhow::Result;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(any(feature = "pcap", target_os = "macos"))]
mod libpcap;

/// Where the bytes of a frame start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Ethernet,
    /// No link header: the bytes start at the IP header.
    Ip,
}

/// A captured frame, borrowed from the backend until the next read.
pub struct Frame<'a> {
    /// The bytes captured, cut at the snap length.
    pub data: &'a [u8],
    /// The length of the frame on the wire.
    pub length: u32,
}

pub trait Capture {
    /// The link type of every frame this capture yields.
    fn link(&self) -> Link;

    /// Waits up to about a second for a frame, so the caller keeps
    /// servicing its timers on an idle link.
    fn next_frame(&mut self) -> Option<Frame<'_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    /// The native backend of this platform
    Auto,
    /// AF_PACKET mmap ring (Linux only)
    AfPacket,
    /// libpcap / Npcap
    Pcap,
}

/// `filter` is a tcpdump expression; it needs libpcap to compile, so
/// only builds with the `pcap` feature offer it.
pub fn open(
    backend: Backend,
    interface: &str,
    promiscuous: bool,
    filter: Option<&str>,
) -> Result<Box<dyn Capture>> {
    match backend {
        Backend::Auto if cfg!(target_os = "linux") => {
            open_af_packet(interface, promiscuous, filter)
        }
        Backend::Auto | Backend::Pcap => open_pcap(interface, promiscuous, filter),
        Backend::AfPacket => open_af_packet(interface, promiscuous, filter),
    }
}

#[cfg(target_os = "linux")]
fn open_af_packet(
    interface: &str,
    promiscuous: bool,
    filter: Option<&str>,
) -> Result<Box<dyn Capture>> {
    let program: Option<Vec<libc::sock_filter>> = match filter {
        #[cfg(feature = "pcap")]
        Some(expression) => Some(libpcap::compile(expression, af_packet::SNAPLEN)?),
        #[cfg(not(feature = "pcap"))]
        Some(_) => anyhow::bail!("Filters need a build with the `pcap` feature"),
        None => None,
    };
    Ok(Box::new(af_packet::AfPacket::new(
        interface,
        promiscuous,
        program.as_deref(),
    )?))
}

#[cfg(not(target_os = "linux"))]
fn open_af_packet(_: &str, _: bool, _: Option<&str>) -> Result<Box<dyn Capture>> {
    anyhow::bail!("The af-packet capture backend requires Linux; use --capture pcap")
}

#[cfg(any(feature = "pcap", target_os = "macos"))]
fn open_pcap(interface: &str, promiscuous: bool, filter: Option<&str>) -> Result<Box<dyn Capture>> {
    Ok(Box::new(libpcap::Libpcap::new(
        interface,
        promiscuous,
        filter,
    )?))
}

#[cfg(not(any(feature = "pcap", target_os = "macos")))]
fn open_pcap(_: &str, _: bool, _: Option<&str>) -> Result<Box<dyn Capture>> {
    anyhow::bail!("This build has no pcap support; rebuild with `--features pcap`")
}
