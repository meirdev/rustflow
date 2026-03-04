use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;
use tokio::net::UdpSocket;

use crate::processor::{NetflowProcessor, SflowProcessor};
use crate::reader::{NetflowReadResult, SflowReadResult};

/// An async reader for NetFlow (v5, v9) and IPFIX data.
pub struct NetflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: NetflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl NetflowReader {
    /// Bind to a UDP socket and create a new async NetFlow reader.
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
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
    pub async fn read_raw(&mut self) -> io::Result<NetflowReadResult> {
        let (len, src_addr) = self.socket.recv_from(&mut self.buf).await?;

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
    pub async fn read(&mut self) -> io::Result<CommonFlow> {
        loop {
            // Return pending flows first
            if let Some(flow) = self.pending_flows.pop_front() {
                return Ok(flow);
            }

            // Read from socket
            let (len, src_addr) = self.socket.recv_from(&mut self.buf).await?;

            let src = src_addr.ip();
            let payload = &self.buf[..len];
            let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

            self.pending_flows
                .extend(self.processor.process(src, payload, time_received_ns));
        }
    }
}

/// An async reader for sFlow v5 data.
pub struct SflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: SflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl SflowReader {
    /// Bind to a UDP socket and create a new async sFlow reader.
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            processor: SflowProcessor::new(),
            pending_flows: VecDeque::new(),
        })
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
    pub async fn read_raw(&mut self) -> io::Result<SflowReadResult> {
        let (len, src_addr) = self.socket.recv_from(&mut self.buf).await?;

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
    pub async fn read(&mut self) -> io::Result<CommonFlow> {
        loop {
            // Return pending flows first
            if let Some(flow) = self.pending_flows.pop_front() {
                return Ok(flow);
            }

            // Read from socket
            let (len, _src_addr) = self.socket.recv_from(&mut self.buf).await?;

            let payload = &self.buf[..len];
            let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

            self.pending_flows
                .extend(self.processor.process(payload, time_received_ns));
        }
    }
}
