use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{fmt, io};

use jiff::Timestamp;
use socket2::SockRef;

/// How often a socket without a read timeout of its own wakes up to see
/// whether it was stopped.
const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// The largest UDP payload.
pub(super) const MAX_DATAGRAM: usize = 65_535;

/// One datagram, as a source received it.
#[derive(Debug, Clone, Copy)]
pub struct Datagram<'a> {
    pub payload: &'a [u8],
    pub from: SocketAddr,
    pub received: Timestamp,
    /// The clock that templates and other state expire by.
    pub now: Instant,
}

/// What one receive turned up.
#[derive(Debug, Clone, Copy)]
pub enum Recv<'a> {
    Datagram(Datagram<'a>),
    /// No datagram before the read timeout.
    Timeout,
    /// The end of a capture.
    End,
}

pub trait Source {
    fn recv(&mut self) -> io::Result<Recv<'_>>;
}

pub struct UdpSource {
    socket: UdpSocket,
    buffer: Vec<u8>,
    stopped: Arc<AtomicBool>,
}

impl UdpSource {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            buffer: vec![0; MAX_DATAGRAM],
            stopped: Arc::default(),
        }
    }

    pub fn bind(address: impl ToSocketAddrs) -> io::Result<Self> {
        UdpSocket::bind(address).map(Self::new)
    }

    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
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

    pub fn stop_handle(&self) -> io::Result<StopHandle> {
        if self.socket.read_timeout()?.is_none() {
            self.socket.set_read_timeout(Some(STOP_CHECK_INTERVAL))?;
        }
        Ok(StopHandle(Arc::clone(&self.stopped)))
    }
}

#[derive(Debug, Clone)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for UdpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSource")
            .field("socket", &self.socket)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

impl Source for UdpSource {
    fn recv(&mut self) -> io::Result<Recv<'_>> {
        if self.stopped.load(Ordering::Relaxed) {
            return Ok(Recv::End);
        }
        match self.socket.recv_from(&mut self.buffer) {
            Ok((length, from)) => Ok(Recv::Datagram(Datagram {
                payload: &self.buffer[..length],
                from,
                received: Timestamp::now(),
                now: Instant::now(),
            })),
            // A read timeout, a non-blocking miss, or a signal interrupting
            // the wait: no datagram this time, not a socket error.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                // A timeout, unless it was the wake-up of a stop.
                Ok(if self.stopped.load(Ordering::Relaxed) {
                    Recv::End
                } else {
                    Recv::Timeout
                })
            }
            Err(error) => Err(error),
        }
    }
}
