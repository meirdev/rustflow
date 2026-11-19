use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::{Block, PcapNgReader};

use super::source::{Datagram, Recv, Source};
use crate::net::{self, Protocol};

/// How a pcapng file starts: its Section Header Block type.
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// The UDP datagrams of a pcap or pcapng capture, received when they were
/// captured.
pub struct PcapSource<R: Read> {
    capture: Capture<R>,
    port: Option<u16>,
    /// The capture time of the first datagram, and the `Instant` it stands
    /// for, so that templates expire by the capture's clock rather than by
    /// how fast it is read.
    clock: Option<(Duration, Instant)>,
    buffer: Vec<u8>,
}

enum Capture<R: Read> {
    Pcap(PcapReader<R>),
    PcapNg {
        reader: PcapNgReader<R>,
        /// By interface ID.
        interfaces: Vec<Interface>,
    },
}

/// What a pcapng interface says of the packets captured on it.
#[derive(Debug, Clone, Copy)]
struct Interface {
    link: DataLink,
    /// `if_tsresol`: the unit of a timestamp. The top bit set, the rest is
    /// a negative power of 2; clear, of 10.
    resolution: u8,
    /// `if_tsoffset`: seconds to add to a timestamp, signed.
    offset: i64,
}

impl Interface {
    /// Microseconds, when `if_tsresol` is absent.
    const DEFAULT_RESOLUTION: u8 = 6;
    const BINARY_RESOLUTION: u8 = 0x80;

    fn new(block: &InterfaceDescriptionBlock<'_>) -> Self {
        let mut interface = Self {
            link: block.linktype,
            resolution: Self::DEFAULT_RESOLUTION,
            offset: 0,
        };
        for option in &block.options {
            match *option {
                InterfaceDescriptionOption::IfTsResol(resolution) => {
                    interface.resolution = resolution;
                }
                InterfaceDescriptionOption::IfTsOffset(offset) => interface.offset = offset as i64,
                _ => {}
            }
        }
        interface
    }

    /// The time since the Unix epoch of a timestamp, given as pcap-file
    /// gives it: its ticks, as nanoseconds whatever the resolution.
    fn time(&self, timestamp: Duration) -> Duration {
        let ticks = timestamp.as_nanos();
        let power = u32::from(self.resolution & !Self::BINARY_RESOLUTION);
        let nanos = if self.resolution & Self::BINARY_RESOLUTION != 0 {
            (ticks * 1_000_000_000).checked_shr(power).unwrap_or(0)
        } else if power <= 9 {
            ticks * 10u128.pow(9 - power)
        } else {
            ticks / 10u128.checked_pow(power - 9).unwrap_or(u128::MAX)
        };
        let time = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        let offset = Duration::from_secs(self.offset.unsigned_abs());
        if self.offset < 0 {
            time.saturating_sub(offset)
        } else {
            time.saturating_add(offset)
        }
    }
}

impl Default for Interface {
    /// For a packet of an interface no block described.
    fn default() -> Self {
        Self {
            link: DataLink::ETHERNET,
            resolution: Self::DEFAULT_RESOLUTION,
            offset: 0,
        }
    }
}

impl<R: Read> fmt::Debug for PcapSource<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcapSource")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl PcapSource<BufReader<File>> {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(BufReader::new(File::open(path)?))
    }
}

impl<R: BufRead> PcapSource<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let capture = if reader.fill_buf()?.starts_with(&PCAPNG_MAGIC) {
            Capture::PcapNg {
                reader: PcapNgReader::new(reader).map_err(invalid_data)?,
                interfaces: Vec::new(),
            }
        } else {
            Capture::Pcap(PcapReader::new(reader).map_err(invalid_data)?)
        };
        Ok(Self {
            capture,
            port: None,
            clock: None,
            buffer: Vec::new(),
        })
    }
}

impl<R: Read> PcapSource<R> {
    /// Only the datagrams sent to or from `port`.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

impl<R: Read> Source for PcapSource<R> {
    fn recv(&mut self) -> io::Result<Recv<'_>> {
        loop {
            let datagram = match &mut self.capture {
                Capture::Pcap(reader) => {
                    let link = reader.header().datalink;
                    let Some(packet) = reader.next_packet() else {
                        return Ok(Recv::End);
                    };
                    let packet = packet.map_err(invalid_data)?;
                    udp_payload(link, &packet.data, self.port, &mut self.buffer)
                        .map(|from| (packet.timestamp, from))
                }
                Capture::PcapNg { reader, interfaces } => {
                    let Some(block) = reader.next_block() else {
                        return Ok(Recv::End);
                    };
                    match block.map_err(invalid_data)? {
                        // A new section numbers its interfaces anew.
                        Block::SectionHeader(_) => {
                            interfaces.clear();
                            None
                        }
                        Block::InterfaceDescription(block) => {
                            interfaces.push(Interface::new(&block));
                            None
                        }
                        Block::EnhancedPacket(packet) => {
                            let interface = interfaces
                                .get(packet.interface_id as usize)
                                .copied()
                                .unwrap_or_default();
                            udp_payload(interface.link, &packet.data, self.port, &mut self.buffer)
                                .map(|from| (interface.time(packet.timestamp), from))
                        }
                        _ => None,
                    }
                }
            };
            let Some((captured, from)) = datagram else {
                continue;
            };

            let (first_capture, first_instant) =
                *self.clock.get_or_insert((captured, Instant::now()));
            return Ok(Recv::Datagram(Datagram {
                payload: &self.buffer,
                from,
                received: Timestamp::new(captured.as_secs() as i64, captured.subsec_nanos() as i32)
                    .unwrap_or(Timestamp::UNIX_EPOCH),
                now: first_instant + captured.saturating_sub(first_capture),
            }));
        }
    }
}

/// Copies the UDP payload of a link-layer frame into `buffer`, if it is one
/// to or from `port`, and gives its source. Tunnels are not looked into:
/// this is the outermost UDP datagram.
fn udp_payload(
    link: DataLink,
    frame: &[u8],
    port: Option<u16>,
    buffer: &mut Vec<u8>,
) -> Option<SocketAddr> {
    let mut input = frame;
    let mut protocol = match link {
        DataLink::ETHERNET => net::ethernet(&mut input).protocol()?,
        DataLink::LINUX_SLL => net::sll(&mut input).protocol()?,
        DataLink::LINUX_SLL2 => net::sll2(&mut input).protocol()?,
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => ip_version(input)?,
        // BSD loopback: a 4-octet address family, then the IP packet.
        DataLink::NULL | DataLink::LOOP => {
            input = input.get(4..)?;
            ip_version(input)?
        }
        _ => return None,
    };
    while protocol == Protocol::Vlan {
        protocol = net::vlan(&mut input).protocol()?;
    }

    let (source, protocol): (IpAddr, Protocol) = match protocol {
        Protocol::Ipv4 => {
            let ip = net::ipv4(&mut input);
            (ip.source()?.into(), ip.protocol()?)
        }
        Protocol::Ipv6 => {
            let ip = net::ipv6(&mut input);
            (ip.source()?.into(), ip.protocol()?)
        }
        _ => return None,
    };
    if protocol != Protocol::Udp {
        return None;
    }
    let udp = net::udp(&mut input);
    let (source_port, destination_port) = (udp.source()?, udp.destination()?);
    if port.is_some_and(|port| source_port != port && destination_port != port) {
        return None;
    }
    // The UDP length leaves out any link-layer padding after the datagram.
    let payload_length = usize::from(udp.length()?).checked_sub(8)?;
    let payload = input.get(..payload_length).unwrap_or(input);

    buffer.clear();
    buffer.extend_from_slice(payload);
    Some(SocketAddr::new(source, source_port))
}

fn ip_version(packet: &[u8]) -> Option<Protocol> {
    match packet.first()? >> 4 {
        4 => Some(Protocol::Ipv4),
        6 => Some(Protocol::Ipv6),
        _ => None,
    }
}

fn invalid_data(error: pcap_file::PcapError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
