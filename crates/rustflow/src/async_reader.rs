use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;
use socket2::SockRef;
use tokio::net::UdpSocket;

use crate::processor::{NetflowProcessor, Processor, SflowProcessor};
use crate::reader::ReadResult;

/// The async counterpart of [`crate::Reader`].
pub struct Reader<P: Processor> {
    socket: UdpSocket,
    buf: Vec<u8>,
    processor: P,
    pending_flows: VecDeque<CommonFlow>,
}

/// An async reader for NetFlow (v5, v9) and IPFIX data.
pub type NetflowReader = Reader<NetflowProcessor>;

/// An async reader for sFlow v5 data.
pub type SflowReader = Reader<SflowProcessor>;

impl<P: Processor> Reader<P> {
    /// Bind to a UDP socket.
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
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
    pub async fn read_raw(&mut self) -> io::Result<ReadResult<P>> {
        let (len, src_addr) = self.socket.recv_from(&mut self.buf).await?;
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
    pub async fn read(&mut self) -> io::Result<CommonFlow> {
        loop {
            if let Some(flow) = self.pending_flows.pop_front() {
                return Ok(flow);
            }
            let (len, src_addr) = self.socket.recv_from(&mut self.buf).await?;
            let payload = &self.buf[..len];
            let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

            self.pending_flows.extend(self.processor.process(
                src_addr.ip(),
                payload,
                time_received_ns,
            ));
        }
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
