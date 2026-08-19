use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;

use crate::processor::{NetflowPacket, NetflowProcessor, SflowPacket, SflowProcessor};

/// Result of reading a raw NetFlow/IPFIX packet.
#[derive(Debug)]
pub enum NetflowReadResult {
    /// Successfully parsed a packet.
    Packet {
        len: usize,
        src: IpAddr,
        packet: NetflowPacket,
    },
    /// Received data but failed to parse it.
    ParseError {
        len: usize,
        src: IpAddr,
        version: Option<u16>,
    },
    /// No data available (timeout or would block).
    Timeout,
}

/// Result of reading a raw sFlow packet.
#[derive(Debug)]
pub enum SflowReadResult {
    /// Successfully parsed a packet.
    Packet {
        len: usize,
        src: IpAddr,
        packet: SflowPacket,
    },
    /// Received data but failed to parse it.
    ParseError {
        len: usize,
        src: IpAddr,
        version: Option<u32>,
    },
    /// No data available (timeout or would block).
    Timeout,
}

/// Transient `recv` outcomes that mean "no datagram this time, try again":
/// a read timeout / non-blocking miss, or a syscall interrupted by a signal
/// (EINTR, e.g. SIGTERM arriving during shutdown). None of these is a
/// socket error worth reporting.
fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// A reader for NetFlow (v5, v9) and IPFIX data.
pub struct NetflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: NetflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl NetflowReader {
    /// Bind to a UDP socket and create a new NetFlow reader.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            processor: NetflowProcessor::new(),
            pending_flows: VecDeque::new(),
        })
    }

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

    /// Set a read timeout on the socket.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    /// Get the local address this reader is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get a reference to the underlying processor.
    pub fn processor(&self) -> &NetflowProcessor {
        &self.processor
    }

    /// Get a mutable reference to the underlying processor.
    pub fn processor_mut(&mut self) -> &mut NetflowProcessor {
        &mut self.processor
    }

    /// Read the next raw packet from the socket.
    pub fn read_raw(&mut self) -> io::Result<NetflowReadResult> {
        // Read from socket
        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(NetflowReadResult::Timeout),
            Err(e) => return Err(e),
        };

        let src = src_addr.ip();
        let payload = &self.buf[..len];

        match self.processor.parse_raw(src, payload) {
            Some(packet) => Ok(NetflowReadResult::Packet { len, src, packet }),
            None => {
                let version = if len >= 2 {
                    Some(u16::from_be_bytes([self.buf[0], self.buf[1]]))
                } else {
                    None
                };
                Ok(NetflowReadResult::ParseError { len, src, version })
            }
        }
    }

    /// Read the next flow from the socket.
    /// Returns `None` if a read timeout occurs.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop_front() {
            return Ok(Some(flow));
        }

        // Read from socket
        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(None),
            Err(e) => return Err(e),
        };

        let src = src_addr.ip();
        let payload = &self.buf[..len];
        let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

        self.pending_flows
            .extend(self.processor.process(src, payload, time_received_ns));

        // Return the first pending flow
        Ok(self.pending_flows.pop_front())
    }
}

impl Iterator for NetflowReader {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Some(flow)) => return Some(Ok(flow)),
                Ok(None) => continue, // timeout or no data, try again
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// A reader for sFlow v5 data.
pub struct SflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: SflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl SflowReader {
    /// Bind to a UDP socket and create a new sFlow reader.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            processor: SflowProcessor::new(),
            pending_flows: VecDeque::new(),
        })
    }

    /// Set a read timeout on the socket.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    /// Get the local address this reader is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get a reference to the underlying processor.
    pub fn processor(&self) -> &SflowProcessor {
        &self.processor
    }

    /// Get a mutable reference to the underlying processor.
    pub fn processor_mut(&mut self) -> &mut SflowProcessor {
        &mut self.processor
    }

    /// Read the next raw packet from the socket.
    pub fn read_raw(&mut self) -> io::Result<SflowReadResult> {
        // Read from socket
        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(SflowReadResult::Timeout),
            Err(e) => return Err(e),
        };

        let src = src_addr.ip();
        let payload = &self.buf[..len];

        match self.processor.parse_raw(payload) {
            Some(packet) => Ok(SflowReadResult::Packet { len, src, packet }),
            None => {
                let version = if len >= 4 {
                    Some(u32::from_be_bytes([
                        self.buf[0],
                        self.buf[1],
                        self.buf[2],
                        self.buf[3],
                    ]))
                } else {
                    None
                };
                Ok(SflowReadResult::ParseError { len, src, version })
            }
        }
    }

    /// Read the next flow from the socket.
    /// Returns `None` if a read timeout occurs.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop_front() {
            return Ok(Some(flow));
        }

        // Read from socket
        let (len, _src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if is_retryable(&e) => return Ok(None),
            Err(e) => return Err(e),
        };

        let payload = &self.buf[..len];
        let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

        self.pending_flows
            .extend(self.processor.process(payload, time_received_ns));

        // Return the first pending flow
        Ok(self.pending_flows.pop_front())
    }
}

impl Iterator for SflowReader {
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
