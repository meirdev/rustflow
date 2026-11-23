use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use std::{fmt, io};

use futures_core::Stream;
use jiff::Timestamp;
use socket2::SockRef;
use tokio::io::ReadBuf;
use tokio::net::{ToSocketAddrs, UdpSocket};

use super::source::{Datagram, MAX_DATAGRAM};
use super::{
    Batch, NetflowProcessor, Processor, Raw, Read, SflowProcessor, queue_flows, read_batch,
    read_packet,
};
use crate::common_flow::CommonFlow;

pub type AsyncNetflowReader = AsyncReader<NetflowProcessor>;
pub type AsyncSflowReader = AsyncReader<SflowProcessor>;

pub struct AsyncReader<P> {
    socket: UdpSocket,
    buffer: Vec<u8>,
    processor: P,
    pending: VecDeque<CommonFlow>,
}

impl<P: fmt::Debug> fmt::Debug for AsyncReader<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncReader")
            .field("socket", &self.socket)
            .field("processor", &self.processor)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl<P: Processor + Default> AsyncReader<P> {
    pub async fn bind(address: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self::new(UdpSocket::bind(address).await?, P::default()))
    }
}

impl<P: Processor> AsyncReader<P> {
    pub fn new(socket: UdpSocket, processor: P) -> Self {
        Self {
            socket,
            buffer: vec![0; MAX_DATAGRAM],
            processor,
            pending: VecDeque::new(),
        }
    }

    pub fn with_recv_buffer_size(self, size: usize) -> io::Result<Self> {
        SockRef::from(&self.socket).set_recv_buffer_size(size)?;
        Ok(self)
    }

    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        SockRef::from(&self.socket).recv_buffer_size()
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn processor(&self) -> &P {
        &self.processor
    }

    pub fn processor_mut(&mut self) -> &mut P {
        &mut self.processor
    }

    pub async fn read_datagram(&mut self) -> io::Result<Read<Batch>> {
        poll_fn(|cx| self.poll_read_datagram(cx)).await
    }

    pub async fn read_raw(&mut self) -> io::Result<Read<Raw<P::Packet>>> {
        poll_fn(|cx| self.poll_read_raw(cx)).await
    }

    pub async fn read(&mut self) -> io::Result<Read<CommonFlow>> {
        poll_fn(|cx| self.poll_read(cx)).await
    }

    pub fn flows(self) -> AsyncFlows<P> {
        AsyncFlows(self)
    }

    pub fn raw(self) -> AsyncRawReads<P> {
        AsyncRawReads(self)
    }

    pub fn packets(self) -> AsyncPackets<P> {
        AsyncPackets(self)
    }

    fn poll_read_datagram(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Read<Batch>>> {
        let (length, from) = ready!(self.poll_recv(cx))?;
        let datagram = datagram(&self.buffer[..length], from);
        Poll::Ready(Ok(read_batch(&mut self.processor, datagram)))
    }

    fn poll_read_raw(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Read<Raw<P::Packet>>>> {
        let (length, from) = ready!(self.poll_recv(cx))?;
        let datagram = datagram(&self.buffer[..length], from);
        Poll::Ready(Ok(read_packet(&mut self.processor, datagram)))
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Read<CommonFlow>>> {
        loop {
            if let Some(flow) = self.pending.pop_front() {
                return Poll::Ready(Ok(Read::Item(flow)));
            }
            let (length, from) = ready!(self.poll_recv(cx))?;
            let datagram = datagram(&self.buffer[..length], from);
            if let Some(malformed) = queue_flows(&mut self.processor, datagram, &mut self.pending) {
                return Poll::Ready(Ok(malformed));
            }
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buffer = ReadBuf::new(&mut self.buffer);
        let from = ready!(self.socket.poll_recv_from(cx, &mut buffer))?;
        Poll::Ready(Ok((buffer.filled().len(), from)))
    }
}

impl<P: Processor + Unpin> Stream for AsyncReader<P> {
    type Item = io::Result<Read<CommonFlow>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_read(cx).map(Some)
    }
}

#[derive(Debug)]
pub struct AsyncFlows<P>(AsyncReader<P>);

#[derive(Debug)]
pub struct AsyncRawReads<P>(AsyncReader<P>);

#[derive(Debug)]
pub struct AsyncPackets<P>(AsyncReader<P>);

impl<P> AsyncFlows<P> {
    pub fn reader(&self) -> &AsyncReader<P> {
        &self.0
    }
}

impl<P> AsyncRawReads<P> {
    pub fn reader(&self) -> &AsyncReader<P> {
        &self.0
    }
}

impl<P> AsyncPackets<P> {
    pub fn reader(&self) -> &AsyncReader<P> {
        &self.0
    }
}

impl<P: Processor + Unpin> Stream for AsyncFlows<P> {
    type Item = io::Result<CommonFlow>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let reader = &mut self.get_mut().0;
        poll_item(|| reader.poll_read(cx))
    }
}

impl<P: Processor + Unpin> Stream for AsyncRawReads<P> {
    type Item = io::Result<Read<Raw<P::Packet>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().0.poll_read_raw(cx).map(Some)
    }
}

impl<P: Processor + Unpin> Stream for AsyncPackets<P> {
    type Item = io::Result<Raw<P::Packet>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let reader = &mut self.get_mut().0;
        poll_item(|| reader.poll_read_raw(cx))
    }
}

fn poll_item<T>(
    mut poll_read: impl FnMut() -> Poll<io::Result<Read<T>>>,
) -> Poll<Option<io::Result<T>>> {
    loop {
        match ready!(poll_read()) {
            Ok(Read::Item(item)) => return Poll::Ready(Some(Ok(item))),
            Ok(Read::Malformed { .. } | Read::Timeout) => {}
            Err(error) => return Poll::Ready(Some(Err(error))),
        }
    }
}

fn datagram(payload: &[u8], from: SocketAddr) -> Datagram<'_> {
    Datagram {
        payload,
        from,
        received: Timestamp::now(),
        now: Instant::now(),
    }
}
