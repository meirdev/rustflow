use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use chrono::Utc;
use pcap_file::pcap::PcapReader;
use rustflow_core::common::packet::parse_udp_packet;

use crate::SHUTDOWN;

pub enum Datagram<'a> {
    Packet {
        src: IpAddr,
        payload: &'a [u8],
        /// Unix time in nanoseconds: socket receipt time or pcap capture time.
        time_received_ns: Option<i64>,
    },
    /// No packet this time; let the collector flush before trying again.
    Idle,
    /// Input ended: socket shutdown, pcap EOF, or a pcap read error.
    End,
}

pub trait Source {
    /// Read until a datagram, idle event, or end of input is available.
    fn next(&mut self) -> Datagram<'_>;
}

/// Timeouts and interrupted reads yield control for flushing and shutdown
/// checks.
fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

pub struct Socket {
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Socket {
    /// Bind with a read timeout so idle reads allow flushing and shutdown
    /// checks.
    pub fn bind(addr: SocketAddr, read_timeout: Duration) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(read_timeout))?;
        Ok(Self {
            socket,
            buf: vec![0; 65535],
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl Source for Socket {
    fn next(&mut self) -> Datagram<'_> {
        if SHUTDOWN.load(Ordering::Relaxed) {
            return Datagram::End;
        }
        match self.socket.recv_from(&mut self.buf) {
            Ok((len, addr)) => Datagram::Packet {
                src: addr.ip(),
                payload: &self.buf[..len],
                time_received_ns: Some(Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            },
            Err(e) if is_retryable(&e) => Datagram::Idle,
            Err(e) => {
                eprintln!("Error receiving data: {:#?}", e);
                Datagram::Idle
            }
        }
    }
}

/// The UDP payloads of a pcap file, stamped with the capture time.
pub struct Pcap {
    reader: PcapReader<File>,
    payload: Vec<u8>,
}

impl Pcap {
    pub fn open(path: &Path) -> io::Result<Self> {
        let reader = PcapReader::new(File::open(path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            reader,
            payload: Vec::new(),
        })
    }
}

impl Source for Pcap {
    fn next(&mut self) -> Datagram<'_> {
        loop {
            if SHUTDOWN.load(Ordering::Relaxed) {
                return Datagram::End;
            }
            let link_type = self.reader.header().datalink.into();
            match self.reader.next_packet() {
                Some(Ok(packet)) => {
                    let Some((src, payload)) = parse_udp_packet(link_type, &packet.data) else {
                        continue;
                    };
                    let time_received_ns = Some(packet.timestamp.as_nanos() as i64);
                    self.payload = payload;
                    return Datagram::Packet {
                        src,
                        payload: &self.payload,
                        time_received_ns,
                    };
                }
                Some(Err(e)) => {
                    eprintln!("Error reading pcap: {}", e);
                    return Datagram::End;
                }
                None => return Datagram::End,
            }
        }
    }
}
