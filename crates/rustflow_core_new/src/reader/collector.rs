//! Datagrams to records, with the state each exporter's protocols need
//! between datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::convert::{Received, Record, ipfix, netflow_v5, netflow_v9, sflow_v5};
use crate::protocol::information_element::Registry;
use crate::protocol::{Family, ParseError, Protocol};
use crate::reader::pending::{Held, PendingLimits, PendingStats};

/// Sessions one collector may keep state for; the network decides how many
/// exporters send to it.
const MAX_SESSIONS: usize = 65_536;

/// Turns datagrams of one family into records. A session, one per exporter
/// transport address, keeps the templates and options its protocols need
/// between datagrams, scoped by transport session as RFC 7011 requires. A
/// session not heard from for the template timeout is forgotten, its
/// templates having expired by then; datagrams of a new session past
/// [`MAX_SESSIONS`] are dropped.
pub struct Collector {
    family: Family,
    registry: Registry,
    timeout: Duration,
    sessions: HashMap<SocketAddr, Session>,
    next_sweep: Instant,
    pending: Option<PendingLimits>,
    dropped: u64,
}

#[derive(Default)]
struct Session {
    last_seen: Option<Instant>,
    netflow_v9: Option<State<crate::protocol::netflow_v9::Parser, netflow_v9::Converter>>,
    ipfix: Option<State<crate::protocol::ipfix::Parser, ipfix::Converter>>,
    held: Held,
}

/// One protocol's state in a session: the parser keeping its templates,
/// the converter keeping what its options records said.
struct State<P, C> {
    parser: P,
    converter: C,
}

/// The state a templated protocol keeps per session: its parser and
/// converter.
trait TemplatedState {
    type Packet;

    fn new(registry: Registry, timeout: Duration) -> Self;

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError>;

    fn convert(
        &mut self,
        packet: Self::Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    );

    fn has_templates(packet: &Self::Packet) -> bool;

    fn has_undecoded(packet: &Self::Packet) -> bool;
}

impl TemplatedState for State<crate::protocol::netflow_v9::Parser, netflow_v9::Converter> {
    type Packet = crate::protocol::netflow_v9::Packet;

    fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            parser: crate::protocol::netflow_v9::Parser::new(registry, timeout),
            converter: netflow_v9::Converter::default(),
        }
    }

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError> {
        self.parser.parse(datagram)
    }

    fn convert(
        &mut self,
        packet: Self::Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) {
        self.converter.convert(packet, received, records);
    }

    fn has_templates(packet: &Self::Packet) -> bool {
        packet.has_templates()
    }

    fn has_undecoded(packet: &Self::Packet) -> bool {
        packet.has_undecoded()
    }
}

impl TemplatedState for State<crate::protocol::ipfix::Parser, ipfix::Converter> {
    type Packet = crate::protocol::ipfix::Packet;

    fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            parser: crate::protocol::ipfix::Parser::new(registry, timeout),
            converter: ipfix::Converter::default(),
        }
    }

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError> {
        self.parser.parse(datagram)
    }

    fn convert(
        &mut self,
        packet: Self::Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) {
        self.converter.convert(packet, received, records);
    }

    fn has_templates(packet: &Self::Packet) -> bool {
        packet.has_templates()
    }

    fn has_undecoded(packet: &Self::Packet) -> bool {
        packet.has_undecoded()
    }
}

impl Collector {
    /// Collects `family`, with fields looked up in `registry`; a template
    /// expires `timeout` after it was last received. [`Collector::of`] takes
    /// the usual registry and timeout.
    pub fn new(family: Family, registry: Registry, timeout: Duration) -> Self {
        Self {
            family,
            registry,
            timeout,
            sessions: HashMap::new(),
            next_sweep: Instant::now() + timeout,
            pending: None,
            dropped: 0,
        }
    }

    /// Holds NetFlow v9 and IPFIX datagrams whose data came before its
    /// template, within `limits`, and converts them once a later datagram of
    /// their session brings templates, before that datagram's own records.
    /// Their records keep the receive time of the datagram they came in.
    ///
    /// A template ID an exporter reuses for another template within
    /// `max_age` decodes the datagrams held for the old one wrongly (RFC
    /// 7011 section 9); a short `max_age` keeps that window small.
    pub fn with_pending(mut self, limits: PendingLimits) -> Self {
        self.pending = Some(limits);
        self
    }

    /// What is held for templates not received yet; `None` unless
    /// [`Collector::with_pending`] set limits.
    pub fn pending(&self) -> Option<PendingStats> {
        self.pending.map(|_| PendingStats {
            held_bytes: self
                .sessions
                .values()
                .map(|session| session.held.bytes())
                .sum(),
            dropped_datagrams: self.dropped,
        })
    }

    /// Collects `family` with IANA's registry and templates that expire
    /// after ten minutes.
    pub fn of(family: Family) -> Self {
        Self::new(family, Registry::iana(), Duration::from_mins(10))
    }

    /// Converts a datagram's records, adding them to `records`, by the
    /// version at its start.
    pub fn collect(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        match Protocol::of(self.family, datagram)? {
            Protocol::NetflowV5 => netflow_v5::convert(
                crate::protocol::netflow_v5::parse(datagram)?,
                &received,
                records,
            ),
            Protocol::NetflowV9 => {
                self.collect_templated(received, datagram, records, |session| {
                    (&mut session.netflow_v9, &mut session.held)
                })?;
            }
            Protocol::Ipfix => {
                self.collect_templated(received, datagram, records, |session| {
                    (&mut session.ipfix, &mut session.held)
                })?;
            }
            Protocol::SflowV5 => sflow_v5::convert(
                crate::protocol::sflow_v5::parse(datagram)?,
                &received,
                records,
            ),
        }
        Ok(())
    }

    /// Collects a datagram of a templated protocol through its session's
    /// state and held datagrams, `parts_of` the session, with the datagrams
    /// held for templates it brings converted first.
    fn collect_templated<T: TemplatedState>(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
        parts_of: impl Fn(&mut Session) -> (&mut Option<T>, &mut Held),
    ) -> Result<(), ParseError> {
        let (registry, timeout, limits) = (self.registry.clone(), self.timeout, self.pending);
        let Some(session) = self.session(received.exporter) else {
            return Ok(());
        };
        let (state, held) = parts_of(session);
        let state = state.get_or_insert_with(|| T::new(registry, timeout));
        let mut dropped = 0;
        let mut packet = state.parse(datagram)?;
        if T::has_templates(&packet) {
            if let Some(limits) = limits {
                let (taken, aged) = held.take(limits);
                dropped += aged;
                for (received, datagram) in taken {
                    match state.parse(&datagram) {
                        Ok(packet) if T::has_undecoded(&packet) => {
                            dropped += held.push(limits, received, &datagram);
                        }
                        Ok(packet) => state.convert(packet, &received, records),
                        Err(_) => dropped += 1,
                    }
                }
            }
            // The template came after the data in the same datagram.
            if T::has_undecoded(&packet) {
                packet = state.parse(datagram)?;
            }
        }
        if let Some(limits) = limits
            && T::has_undecoded(&packet)
        {
            dropped += held.push(limits, received, datagram);
        }
        state.convert(packet, &received, records);
        self.dropped += dropped;
        Ok(())
    }

    /// The latest options record of each kind every session sent, with
    /// the exporter and observation domain it describes.
    pub fn options(&self) -> impl Iterator<Item = (SocketAddr, u32, &Record)> {
        self.sessions.iter().flat_map(|(&exporter, session)| {
            let netflow_v9 = session
                .netflow_v9
                .iter()
                .flat_map(|state| state.converter.options());
            let ipfix = session
                .ipfix
                .iter()
                .flat_map(|state| state.converter.options());
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::protocol::information_element::iana;
    use crate::protocol::value::Value;

    const EXPORTER: ([u8; 4], u16) = ([192, 0, 2, 1], 2055);

    fn words(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn set(id: u16, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(4 + body.len()).unwrap();
        [&words(&[id, length])[..], body].concat()
    }

    /// Template 256: octetDeltaCount(1) in four bytes.
    fn octet_count_template(template_set_id: u16) -> Vec<u8> {
        set(
            template_set_id,
            &words(&[256, 1, iana::OCTET_DELTA_COUNT.id, 4]),
        )
    }

    fn octet_count_data(octets: u32) -> Vec<u8> {
        set(256, &octets.to_be_bytes())
    }

    fn ipfix(sequence_number: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let body = sets.concat();
        let length = u16::try_from(16 + body.len()).unwrap();
        [
            words(&[10, length]),
            1_700_000_000u32.to_be_bytes().to_vec(),
            sequence_number.to_be_bytes().to_vec(),
            7u32.to_be_bytes().to_vec(),
            body,
        ]
        .concat()
    }

    fn netflow_v9(sequence_number: u32, flow_sets: &[Vec<u8>]) -> Vec<u8> {
        let count = u16::try_from(flow_sets.len()).unwrap();
        [
            words(&[9, count]),
            3_600_000u32.to_be_bytes().to_vec(),
            1_700_000_000u32.to_be_bytes().to_vec(),
            sequence_number.to_be_bytes().to_vec(),
            7u32.to_be_bytes().to_vec(),
            flow_sets.concat(),
        ]
        .concat()
    }

    fn received(second: u64) -> Received {
        Received {
            exporter: EXPORTER.into(),
            time: Some(UNIX_EPOCH + Duration::from_secs(second)),
        }
    }

    fn holding() -> Collector {
        Collector::of(Family::Netflow).with_pending(PendingLimits {
            session_bytes: 1 << 10,
            max_age: Duration::from_mins(1),
        })
    }

    fn collect(collector: &mut Collector, second: u64, datagram: &[u8]) -> Vec<Record> {
        let mut records = Vec::new();
        collector
            .collect(received(second), datagram, &mut records)
            .unwrap();
        records
    }

    #[test]
    fn data_sent_before_its_template_comes_out_with_its_own_datagram() {
        let mut collector = holding();
        let early = ipfix(41, &[octet_count_data(5)]);
        assert_eq!(collect(&mut collector, 100, &early), []);
        assert_eq!(
            collector.pending(),
            Some(PendingStats {
                held_bytes: early.len(),
                dropped_datagrams: 0
            })
        );

        let records = collect(
            &mut collector,
            200,
            &ipfix(42, &[octet_count_template(2), octet_count_data(6)]),
        );
        let octets: Vec<_> = records
            .iter()
            .map(|record| record.first(iana::OCTET_DELTA_COUNT).cloned())
            .collect();
        assert_eq!(
            octets,
            [Some(Value::Unsigned32(5)), Some(Value::Unsigned32(6))]
        );
        assert_eq!(records[0].sequence_number, 41);
        assert_eq!(
            records[0].first(iana::COLLECTION_TIME_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(100_000))
        );
        assert_eq!(records[1].sequence_number, 42);
        assert_eq!(collector.pending().unwrap().held_bytes, 0);
    }

    #[test]
    fn netflow_v9_data_before_its_template_in_one_packet_is_decoded() {
        let packet = netflow_v9(9, &[octet_count_data(5), octet_count_template(0)]);
        for mut collector in [holding(), Collector::of(Family::Netflow)] {
            let records = collect(&mut collector, 100, &packet);
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].first(iana::OCTET_DELTA_COUNT),
                Some(&Value::Unsigned32(5))
            );
        }
        assert_eq!(Collector::of(Family::Netflow).pending(), None);
    }

    #[test]
    fn a_session_forgotten_frees_what_it_held() {
        let mut collector = Collector::new(Family::Netflow, Registry::iana(), Duration::ZERO)
            .with_pending(PendingLimits {
                session_bytes: 1 << 10,
                max_age: Duration::from_mins(1),
            });
        collect(&mut collector, 100, &ipfix(41, &[octet_count_data(5)]));
        let other = Received {
            exporter: ([192, 0, 2, 2], 2055).into(),
            time: Some(SystemTime::now()),
        };
        collector
            .collect(other, &ipfix(1, &[]), &mut Vec::new())
            .unwrap();
        assert_eq!(collector.pending().unwrap().held_bytes, 0);
    }
}
