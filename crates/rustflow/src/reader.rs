use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;
use socket2::SockRef;

use crate::processor::{NetflowProcessor, Processor, SflowProcessor};

/// What one datagram turned out to be.
#[derive(Debug)]
pub enum ReadResult<P: Processor> {
    /// Successfully parsed a packet.
    Packet {
        len: usize,
        src: IpAddr,
        packet: P::Packet,
    },
    /// Received data but failed to parse it. `version` names the version
    /// in the header when it is a known one.
    ParseError {
        len: usize,
        src: IpAddr,
        version: Option<&'static str>,
    },
    /// No data available (timeout or would block).
    Timeout,
}

pub type NetflowReadResult = ReadResult<NetflowProcessor>;
pub type SflowReadResult = ReadResult<SflowProcessor>;

/// Transient `recv` outcomes that mean "no datagram this time, try again":
/// a read timeout / non-blocking miss, or a syscall interrupted by a signal
/// (EINTR, e.g. SIGTERM arriving during shutdown). None of these is a
/// socket error worth reporting.
pub(crate) fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Reads one protocol family from a UDP socket and yields normalized
/// flows, one at a time.
pub struct Reader<P: Processor> {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: P,
    pending_flows: VecDeque<CommonFlow>,
}

/// A reader for NetFlow (v5, v9) and IPFIX data.
pub type NetflowReader = Reader<NetflowProcessor>;

/// A reader for sFlow v5 data.
pub type SflowReader = Reader<SflowProcessor>;

impl<P: Processor> Reader<P> {
    /// Bind to a UDP socket.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            processor: P::default(),
            pending_flows: VecDeque::new(),
        })
    }

    /// Decode with a processor configured by hand.
    pub fn with_processor(mut self, processor: P) -> Self {
        self.processor = processor;
        self
    }

    /// Set a read timeout on the socket.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    /// Set the socket receive buffer size.
    pub fn with_recv_buffer_size(self, size: usize) -> io::Result<Self> {
        SockRef::from(&self.socket).set_recv_buffer_size(size)?;
        Ok(self)
    }

    /// Get the receive buffer size the kernel granted.
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        SockRef::from(&self.socket).recv_buffer_size()
    }

    /// Get the local address this reader is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn processor(&self) -> &P {
        &self.processor
    }

    pub fn processor_mut(&mut self) -> &mut P {
        &mut self.processor
    }

    /// Read the next raw packet from the socket.
    pub fn read_raw(&mut self) -> io::Result<ReadResult<P>> {
        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(ReadResult::Timeout),
            Err(e) => return Err(e),
        };
        let src = src_addr.ip();
        let payload = &self.buf[..len];

        Ok(match self.processor.parse(src, payload) {
            Some(packet) => ReadResult::Packet { len, src, packet },
            None => ReadResult::ParseError {
                len,
                src,
                version: P::version_of(payload),
            },
        })
    }

    /// Read the next flow from the socket.
    /// Returns `None` if a read timeout occurs.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        if let Some(flow) = self.pending_flows.pop_front() {
            return Ok(Some(flow));
        }

        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let payload = &self.buf[..len];
        let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

        self.pending_flows.extend(
            self.processor
                .process(src_addr.ip(), payload, time_received_ns),
        );
        Ok(self.pending_flows.pop_front())
    }
}

impl Reader<NetflowProcessor> {
    /// Set a custom IE registry.
    pub fn with_ie_registry(mut self, registry: IERegistry) -> Self {
        self.processor = self.processor.with_ie_registry(registry);
        self
    }

    /// Set the template cache timeout.
    pub fn with_template_timeout(mut self, timeout: Duration) -> Self {
        self.processor = self.processor.with_template_timeout(timeout);
        self
    }
}

impl<P: Processor> Iterator for Reader<P> {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Some(flow)) => return Some(Ok(flow)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
