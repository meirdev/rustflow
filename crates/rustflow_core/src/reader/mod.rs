//! Readers of flow datagrams, from a UDP socket or, with the `pcap`
//! feature, a capture file. A reader reads one family of protocols, and
//! tells the versions apart by the first octets of each datagram: NetFlow
//! v5, NetFlow v9 and IPFIX, or sFlow v5.
//!
//! [`Reader::flows`] yields the [`CommonFlow`]s:
//!
//! ```no_run
//! use rustflow_core::reader::NetflowReader;
//!
//! for flow in NetflowReader::bind("0.0.0.0:2055").unwrap().flows() {
//!     println!("{:?}", flow.unwrap());
//! }
//! ```
//!
//! As an iterator, a reader yields every [`Read`]: the flows, and the
//! timeouts and malformed datagrams between them. [`Reader::raw`] and
//! [`Reader::packets`] are the same for the packets as they are. With the
//! `tokio` feature, an [`AsyncReader`] awaits the datagrams of a socket
//! instead of blocking on them.

#[cfg(feature = "tokio")]
mod async_socket;
#[cfg(feature = "pcap")]
mod pcap;
mod processor;
mod source;

use std::collections::VecDeque;
#[cfg(feature = "pcap")]
use std::fs::File;
#[cfg(feature = "pcap")]
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(feature = "pcap")]
use std::path::Path;
use std::time::Duration;
use std::{fmt, io};

use jiff::Timestamp;
use winnow::error::ContextError;

#[cfg(feature = "tokio")]
pub use self::async_socket::{
    AsyncFlows, AsyncNetflowReader, AsyncPackets, AsyncRawReads, AsyncReader, AsyncSflowReader,
};
#[cfg(feature = "pcap")]
pub use self::pcap::PcapSource;
pub use self::processor::{
    NetflowPacket, NetflowProcessor, Processor, SflowPacket, SflowProcessor,
};
pub use self::source::{Datagram, Recv, Source, StopHandle, UdpSource};
use crate::common_flow::CommonFlow;

pub type NetflowReader = Reader<UdpSource, NetflowProcessor>;
pub type SflowReader = Reader<UdpSource, SflowProcessor>;
#[cfg(feature = "pcap")]
pub type NetflowPcapReader = Reader<PcapSource<BufReader<File>>, NetflowProcessor>;
#[cfg(feature = "pcap")]
pub type SflowPcapReader = Reader<PcapSource<BufReader<File>>, SflowProcessor>;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ReadError {
    /// Too short to hold a version.
    Truncated,
    /// A version the family does not have.
    UnknownVersion(u32),
    Parse {
        version: u32,
        error: ContextError,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the datagram is too short to hold a version"),
            Self::UnknownVersion(version) => write!(f, "unknown version {version}"),
            Self::Parse { version, error } => {
                // winnow puts the label and the expectation on separate
                // lines, and says nothing where no parser labelled it.
                let context = error.to_string().replace('\n', "; ");
                match context.as_str() {
                    "" => write!(f, "the version {version} packet does not parse"),
                    context => {
                        write!(f, "the version {version} packet does not parse: {context}")
                    }
                }
            }
        }
    }
}

impl std::error::Error for ReadError {}

#[derive(Debug)]
pub enum Read<T> {
    Item(T),
    /// A datagram that could not be read; the reader goes on past it.
    Malformed {
        from: SocketAddr,
        error: ReadError,
    },
    /// No datagram before the socket's read timeout.
    Timeout,
}

/// A packet as it is, with where and when it was received.
#[derive(Debug)]
pub struct Raw<T> {
    pub from: SocketAddr,
    pub received: Timestamp,
    pub packet: T,
}

/// Reads the datagrams of `S` as the packets of `P`'s family.
#[derive(Debug)]
pub struct Reader<S, P> {
    source: S,
    processor: P,
    /// The flows of a datagram that are not read yet.
    pending: VecDeque<CommonFlow>,
}

impl<P: Processor + Default> Reader<UdpSource, P> {
    pub fn bind(address: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self::new(UdpSource::bind(address)?, P::default()))
    }
}

impl<P> Reader<UdpSource, P> {
    pub fn with_read_timeout(mut self, timeout: Option<Duration>) -> io::Result<Self> {
        self.source = self.source.with_read_timeout(timeout)?;
        Ok(self)
    }

    pub fn with_recv_buffer_size(mut self, size: usize) -> io::Result<Self> {
        self.source = self.source.with_recv_buffer_size(size)?;
        Ok(self)
    }

    pub fn stop_handle(&self) -> io::Result<StopHandle> {
        self.source.stop_handle()
    }
}

#[cfg(feature = "pcap")]
impl<P: Processor + Default> Reader<PcapSource<BufReader<File>>, P> {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self::new(PcapSource::open(path)?, P::default()))
    }
}

impl<S: Source, P: Processor> Reader<S, P> {
    pub fn new(source: S, processor: P) -> Self {
        Self {
            source,
            processor,
            pending: VecDeque::new(),
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    pub fn processor(&self) -> &P {
        &self.processor
    }

    pub fn read_raw(&mut self) -> io::Result<Option<Read<Raw<P::Packet>>>> {
        Ok(Some(match self.source.recv()? {
            Recv::Datagram(datagram) => read_packet(&mut self.processor, datagram),
            Recv::Timeout => Read::Timeout,
            Recv::End => return Ok(None),
        }))
    }

    pub fn read(&mut self) -> io::Result<Option<Read<CommonFlow>>> {
        loop {
            if let Some(flow) = self.pending.pop_front() {
                return Ok(Some(Read::Item(flow)));
            }
            let datagram = match self.source.recv()? {
                Recv::Datagram(datagram) => datagram,
                Recv::Timeout => return Ok(Some(Read::Timeout)),
                Recv::End => return Ok(None),
            };
            if let Some(malformed) = queue_flows(&mut self.processor, datagram, &mut self.pending) {
                return Ok(Some(malformed));
            }
        }
    }

    pub fn flows(self) -> Flows<S, P> {
        Flows(self)
    }

    pub fn raw(self) -> RawReads<S, P> {
        RawReads(self)
    }

    pub fn packets(self) -> Packets<S, P> {
        Packets(self)
    }
}

impl<S: Source, P: Processor> Iterator for Reader<S, P> {
    type Item = io::Result<Read<CommonFlow>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read().transpose()
    }
}

#[derive(Debug)]
pub struct Flows<S, P>(Reader<S, P>);

#[derive(Debug)]
pub struct RawReads<S, P>(Reader<S, P>);

#[derive(Debug)]
pub struct Packets<S, P>(Reader<S, P>);

impl<S, P> Flows<S, P> {
    pub fn reader(&self) -> &Reader<S, P> {
        &self.0
    }
}

impl<S, P> RawReads<S, P> {
    pub fn reader(&self) -> &Reader<S, P> {
        &self.0
    }
}

impl<S, P> Packets<S, P> {
    pub fn reader(&self) -> &Reader<S, P> {
        &self.0
    }
}

impl<S: Source, P: Processor> Iterator for Flows<S, P> {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        next_item(|| self.0.read())
    }
}

impl<S: Source, P: Processor> Iterator for RawReads<S, P> {
    type Item = io::Result<Read<Raw<P::Packet>>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.read_raw().transpose()
    }
}

impl<S: Source, P: Processor> Iterator for Packets<S, P> {
    type Item = io::Result<Raw<P::Packet>>;

    fn next(&mut self) -> Option<Self::Item> {
        next_item(|| self.0.read_raw())
    }
}

fn next_item<T>(mut read: impl FnMut() -> io::Result<Option<Read<T>>>) -> Option<io::Result<T>> {
    loop {
        match read().transpose()? {
            Ok(Read::Item(item)) => return Some(Ok(item)),
            Ok(Read::Malformed { .. } | Read::Timeout) => {}
            Err(error) => return Some(Err(error)),
        }
    }
}

fn read_packet<P: Processor>(processor: &mut P, datagram: Datagram<'_>) -> Read<Raw<P::Packet>> {
    let from = datagram.from;
    match processor.parse(from.ip(), datagram.payload, datagram.now) {
        Ok(packet) => Read::Item(Raw {
            from,
            received: datagram.received,
            packet,
        }),
        Err(error) => Read::Malformed { from, error },
    }
}

fn queue_flows<P: Processor>(
    processor: &mut P,
    datagram: Datagram<'_>,
    pending: &mut VecDeque<CommonFlow>,
) -> Option<Read<CommonFlow>> {
    let from = datagram.from;
    match processor.parse(from.ip(), datagram.payload, datagram.now) {
        Ok(packet) => {
            let received_ns = nanoseconds(datagram.received);
            processor.convert(from.ip(), &packet, received_ns, datagram.now, pending);
            None
        }
        Err(error) => Some(Read::Malformed { from, error }),
    }
}

fn nanoseconds(time: Timestamp) -> i64 {
    i64::try_from(time.as_nanosecond()).unwrap_or(i64::MAX)
}
