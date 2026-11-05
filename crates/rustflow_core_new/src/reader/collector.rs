//! Datagrams to records, with the state each exporter's protocols need
//! between datagrams.

use std::collections::HashMap;
use std::mem;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::convert::{Received, Record, ipfix, netflow_v5, netflow_v9, sflow_v5};
use crate::protocol::information_element::Registry;
use crate::protocol::{Family, ParseError, Protocol};
use crate::reader::pending::{Budget, Pending, PendingLimits, PendingStats};

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
    pending: Option<Budget>,
}

#[derive(Default)]
struct Session {
    last_seen: Option<Instant>,
    netflow_v9: Option<
        Templated<
            crate::protocol::netflow_v9::Parser,
            netflow_v9::Converter,
            crate::protocol::netflow_v9::Header,
        >,
    >,
    ipfix: Option<
        Templated<crate::protocol::ipfix::Parser, ipfix::Converter, crate::protocol::ipfix::Header>,
    >,
}

impl Session {
    fn held_bytes(&self) -> usize {
        let netflow_v9 = self
            .netflow_v9
            .as_ref()
            .map_or(0, |state| state.pending.bytes());
        let ipfix = self.ipfix.as_ref().map_or(0, |state| state.pending.bytes());
        netflow_v9 + ipfix
    }
}

/// One protocol's state in a session: the parser keeping its templates,
/// the converter keeping what its options records said, and the data sets
/// held for templates not received yet.
struct Templated<P, C, H> {
    parser: P,
    converter: C,
    pending: Pending<H>,
}

impl<P, C: Default, H> Templated<P, C, H> {
    fn new(parser: P) -> Self {
        Self {
            parser,
            converter: C::default(),
            pending: Pending::default(),
        }
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
        }
    }

    /// Holds NetFlow v9 and IPFIX data sets that arrive before their
    /// template, within `limits`, and converts them once a later datagram
    /// of their session brings it, before that datagram's own records.
    /// Their records keep the header and receive time of the datagram they
    /// came in, so they come out after newer ones but with their own times.
    ///
    /// A template ID an exporter reuses for another template within
    /// `max_age` decodes the sets held for the old one wrongly (RFC 7011
    /// section 9); a short `max_age` keeps that window small.
    pub fn with_pending(mut self, limits: PendingLimits) -> Self {
        self.pending = Some(Budget::new(limits));
        self
    }

    /// What is held for templates not received yet; `None` unless
    /// [`Collector::with_pending`] set limits.
    pub fn pending(&self) -> Option<PendingStats> {
        self.pending.as_ref().map(|budget| budget.stats)
    }

    /// Collects `family` with IANA's registry and templates that expire
    /// after ten minutes.
    pub fn of(family: Family) -> Self {
        Self::new(family, Registry::iana(), Duration::from_mins(10))
    }

    pub fn netflow() -> Self {
        Self::of(Family::Netflow)
    }

    pub fn sflow() -> Self {
        Self::of(Family::Sflow)
    }

    /// Converts a datagram's records, adding them to `records`, by the
    /// version at its start.
    pub fn collect(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        let (registry, timeout) = (self.registry.clone(), self.timeout);
        match Protocol::of(self.family, datagram)? {
            Protocol::NetflowV5 => netflow_v5::convert(
                crate::protocol::netflow_v5::parse(datagram)?,
                &received,
                records,
            ),
            Protocol::NetflowV9 => {
                use crate::protocol::netflow_v9::{FlowSet, Packet, Parser};

                if let Some((session, budget)) = self.session(received.exporter) {
                    let state = session
                        .netflow_v9
                        .get_or_insert_with(|| Templated::new(Parser::new(registry, timeout)));
                    let mut packet = state.parser.parse(datagram)?;
                    if let Some(budget) = budget {
                        let undecoded = packet.flow_sets.iter_mut().filter_map(|set| match set {
                            FlowSet::Undecoded { flow_set_id, body } => {
                                Some((*flow_set_id, mem::take(body)))
                            }
                            _ => None,
                        });
                        let source_id = packet.header.source_id;
                        state
                            .pending
                            .hold(budget, received, &packet.header, source_id, undecoded);
                        if packet.flow_sets.iter().any(|set| {
                            matches!(set, FlowSet::Templates(_) | FlowSet::OptionsTemplates(_))
                        }) {
                            let parser = &state.parser;
                            let late = state.pending.release(budget, |source_id, id, body| {
                                Ok::<_, ParseError>(parser.decode(source_id, id, body))
                            });
                            for (received, header, flow_sets) in late {
                                let packet = Packet { header, flow_sets };
                                state.converter.convert(packet, &received, records);
                            }
                        }
                    }
                    state.converter.convert(packet, &received, records);
                }
            }
            Protocol::Ipfix => {
                use crate::protocol::ipfix::{Packet, Parser, Set};

                if let Some((session, budget)) = self.session(received.exporter) {
                    let state = session
                        .ipfix
                        .get_or_insert_with(|| Templated::new(Parser::new(registry, timeout)));
                    let mut packet = state.parser.parse(datagram)?;
                    if let Some(budget) = budget {
                        let undecoded = packet.sets.iter_mut().filter_map(|set| match set {
                            Set::Undecoded { set_id, body } => Some((*set_id, mem::take(body))),
                            _ => None,
                        });
                        let domain = packet.header.observation_domain_id;
                        state
                            .pending
                            .hold(budget, received, &packet.header, domain, undecoded);
                        if packet
                            .sets
                            .iter()
                            .any(|set| matches!(set, Set::Templates(_) | Set::OptionsTemplates(_)))
                        {
                            let parser = &mut state.parser;
                            let late = state.pending.release(budget, |domain, id, body| {
                                parser.decode(domain, id, body)
                            });
                            for (received, header, sets) in late {
                                let packet = Packet { header, sets };
                                state.converter.convert(packet, &received, records);
                            }
                        }
                    }
                    state.converter.convert(packet, &received, records);
                }
            }
            Protocol::SflowV5 => sflow_v5::convert(
                crate::protocol::sflow_v5::parse(datagram)?,
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

    /// The session of `exporter`, marked as heard from now, with the budget
    /// for holding data sets if there is one; `None` for a new session past
    /// [`MAX_SESSIONS`].
    fn session(&mut self, exporter: SocketAddr) -> Option<(&mut Session, Option<&mut Budget>)> {
        let now = Instant::now();
        let new = !self.sessions.contains_key(&exporter);
        if now >= self.next_sweep || (new && self.sessions.len() >= MAX_SESSIONS) {
            let timeout = self.timeout;
            self.sessions.retain(|_, session| {
                let live = session.last_seen.is_some_and(|seen| now - seen < timeout);
                if !live && let Some(budget) = &mut self.pending {
                    budget.stats.held_bytes -= session.held_bytes();
                }
                live
            });
            self.next_sweep = now + timeout;
        }
        if new && self.sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let session = self.sessions.entry(exporter).or_default();
        session.last_seen = Some(now);
        Some((session, self.pending.as_mut()))
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
        Collector::netflow().with_pending(PendingLimits {
            session_bytes: 1 << 10,
            total_bytes: 1 << 20,
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
        assert_eq!(
            collect(&mut collector, 100, &ipfix(41, &[octet_count_data(5)])),
            []
        );
        assert_eq!(
            collector.pending(),
            Some(PendingStats {
                held_bytes: 4,
                dropped_sets: 0
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
        let records = collect(&mut holding(), 100, &packet);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].first(iana::OCTET_DELTA_COUNT),
            Some(&Value::Unsigned32(5))
        );

        let mut without = Collector::netflow();
        assert_eq!(collect(&mut without, 100, &packet), []);
        assert_eq!(without.pending(), None);
    }

    #[test]
    fn a_session_forgotten_frees_what_it_held() {
        let mut collector = Collector::new(Family::Netflow, Registry::iana(), Duration::ZERO)
            .with_pending(PendingLimits {
                session_bytes: 1 << 10,
                total_bytes: 1 << 20,
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
