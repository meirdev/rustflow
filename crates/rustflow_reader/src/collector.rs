//! Datagrams to records, with the state each exporter's protocols need
//! between datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustflow_convert::{Received, Record, ipfix, netflow_v5, netflow_v9, sflow_v5};
use rustflow_protocol::ParseError;
use rustflow_protocol::information_element::Registry;

/// Sessions one collector may keep state for; the network decides how many
/// exporters send to it.
const MAX_SESSIONS: usize = 65_536;

/// Turns datagrams into records. A session, one per exporter transport
/// address, keeps the templates and options its protocols need between
/// datagrams, scoped by transport session as RFC 7011 requires. A session
/// not heard from for the template timeout is forgotten, its templates
/// having expired by then; datagrams of a new session past
/// [`MAX_SESSIONS`] are dropped.
pub struct Collector {
    registry: Registry,
    timeout: Duration,
    sessions: HashMap<SocketAddr, Session>,
    next_sweep: Instant,
}

#[derive(Default)]
struct Session {
    last_seen: Option<Instant>,
    netflow_v9: Option<Templated<rustflow_protocol::netflow_v9::Parser, netflow_v9::Converter>>,
    ipfix: Option<Templated<rustflow_protocol::ipfix::Parser, ipfix::Converter>>,
}

/// One protocol's state in a session: the parser keeping its templates,
/// the converter keeping what its options records said.
struct Templated<P, C> {
    parser: P,
    converter: C,
}

trait Protocol: Sized {
    fn new(registry: Registry, timeout: Duration) -> Self;

    fn collect(
        &mut self,
        datagram: &[u8],
        received: &Received,
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError>;

    fn options(&self) -> impl Iterator<Item = (u32, &Record)>;
}

impl Protocol for Templated<rustflow_protocol::netflow_v9::Parser, netflow_v9::Converter> {
    fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            parser: rustflow_protocol::netflow_v9::Parser::new(registry, timeout),
            converter: netflow_v9::Converter::default(),
        }
    }

    fn collect(
        &mut self,
        datagram: &[u8],
        received: &Received,
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        self.converter
            .convert(self.parser.parse(datagram)?, received, records);
        Ok(())
    }

    fn options(&self) -> impl Iterator<Item = (u32, &Record)> {
        self.converter.options()
    }
}

impl Protocol for Templated<rustflow_protocol::ipfix::Parser, ipfix::Converter> {
    fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            parser: rustflow_protocol::ipfix::Parser::new(registry, timeout),
            converter: ipfix::Converter::default(),
        }
    }

    fn collect(
        &mut self,
        datagram: &[u8],
        received: &Received,
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        self.converter
            .convert(self.parser.parse(datagram)?, received, records);
        Ok(())
    }

    fn options(&self) -> impl Iterator<Item = (u32, &Record)> {
        self.converter.options()
    }
}

impl Collector {
    /// Fields are looked up in `registry`. A template expires `timeout`
    /// after it was last received.
    pub fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            registry,
            timeout,
            sessions: HashMap::new(),
            next_sweep: Instant::now() + timeout,
        }
    }

    /// Converts a datagram's records, adding them to `records`. The
    /// protocol is read from the datagram: NetFlow and IPFIX put their
    /// version in the first two bytes, sFlow in the first four.
    pub fn collect(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        let version = match datagram {
            [0, 0, ..] => rustflow_protocol::sflow_v5::VERSION,
            [high, low, ..] => u32::from(u16::from_be_bytes([*high, *low])),
            _ => 0,
        };
        let (registry, timeout) = (self.registry.clone(), self.timeout);
        match version {
            5 => netflow_v5::convert(
                rustflow_protocol::netflow_v5::parse(datagram)?,
                &received,
                records,
            ),
            9 => {
                if let Some(session) = self.session(received.exporter) {
                    session
                        .netflow_v9
                        .get_or_insert_with(|| Templated::new(registry, timeout))
                        .collect(datagram, &received, records)?;
                }
            }
            10 => {
                if let Some(session) = self.session(received.exporter) {
                    session
                        .ipfix
                        .get_or_insert_with(|| Templated::new(registry, timeout))
                        .collect(datagram, &received, records)?;
                }
            }
            _ => sflow_v5::convert(
                rustflow_protocol::sflow_v5::parse(datagram)?,
                &received,
                records,
            ),
        }
        Ok(())
    }

    /// The latest options record of each kind every session sent, with
    /// the exporter and observation domain it describes.
    pub fn options(&self) -> impl Iterator<Item = (SocketAddr, u32, &Record)> {
        self.sessions.iter().flat_map(|(&exporter, session)| {
            let netflow_v9 = session.netflow_v9.iter().flat_map(Protocol::options);
            let ipfix = session.ipfix.iter().flat_map(Protocol::options);
            netflow_v9
                .chain(ipfix)
                .map(move |(domain, record)| (exporter, domain, record))
        })
    }

    /// The session of `exporter`, marked as heard from now; `None` for a
    /// new one past [`MAX_SESSIONS`].
    fn session(&mut self, exporter: SocketAddr) -> Option<&mut Session> {
        let now = Instant::now();
        let new = !self.sessions.contains_key(&exporter);
        if now >= self.next_sweep || (new && self.sessions.len() >= MAX_SESSIONS) {
            let timeout = self.timeout;
            self.sessions
                .retain(|_, session| session.last_seen.is_some_and(|seen| now - seen < timeout));
            self.next_sweep = now + timeout;
        }
        if new && self.sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let session = self.sessions.entry(exporter).or_default();
        session.last_seen = Some(now);
        Some(session)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new(Registry::iana(), Duration::from_mins(10))
    }
}
