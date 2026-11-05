//! Datagrams to records, with the state each exporter's protocols need
//! between datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::convert::templated::{self, Templated};
use crate::convert::{Received, Record, netflow_v5, sflow_v5};
use crate::protocol::information_element::Registry;
use crate::protocol::{Family, ParseError, Protocol, ipfix, netflow_v9};
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
    netflow_v9: Option<State<netflow_v9::Parser>>,
    ipfix: Option<State<ipfix::Parser>>,
}

/// One protocol's state in a session: the parser keeping its templates,
/// the converter keeping what its options records said, and the sets held
/// for templates not received yet.
struct State<P: TemplatedParser> {
    parser: P,
    converter: templated::Converter<P::Packet>,
    held: Held<P::Packet>,
}

/// A templated protocol's parser, as the collector drives it.
trait TemplatedParser {
    type Packet: Templated;

    fn new(registry: Registry, timeout: Duration) -> Self;

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError>;

    /// Decodes the sets that lacked a template with the templates known
    /// now; sets decoded already keep the template they were decoded with.
    fn resolve(&mut self, packet: &mut Self::Packet);

    fn has_templates(packet: &Self::Packet) -> bool;

    fn has_undecoded(packet: &Self::Packet) -> bool;

    /// Takes the sets that lack a template out of `packet`, as a packet of
    /// their own.
    fn take_undecoded(packet: &mut Self::Packet) -> Self::Packet;
}

impl TemplatedParser for netflow_v9::Parser {
    type Packet = netflow_v9::Packet;

    fn new(registry: Registry, timeout: Duration) -> Self {
        Self::new(registry, timeout)
    }

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError> {
        Self::parse(self, datagram)
    }

    fn resolve(&mut self, packet: &mut Self::Packet) {
        Self::resolve(self, packet);
    }

    fn has_templates(packet: &Self::Packet) -> bool {
        packet.has_templates()
    }

    fn has_undecoded(packet: &Self::Packet) -> bool {
        packet.has_undecoded()
    }

    fn take_undecoded(packet: &mut Self::Packet) -> Self::Packet {
        netflow_v9::Packet {
            header: packet.header.clone(),
            flow_sets: packet
                .flow_sets
                .extract_if(.., |set| {
                    matches!(set, netflow_v9::FlowSet::Undecoded { .. })
                })
                .collect(),
        }
    }
}

impl TemplatedParser for ipfix::Parser {
    type Packet = ipfix::Packet;

    fn new(registry: Registry, timeout: Duration) -> Self {
        Self::new(registry, timeout)
    }

    fn parse(&mut self, datagram: &[u8]) -> Result<Self::Packet, ParseError> {
        Self::parse(self, datagram)
    }

    fn resolve(&mut self, packet: &mut Self::Packet) {
        Self::resolve(self, packet);
    }

    fn has_templates(packet: &Self::Packet) -> bool {
        packet.has_templates()
    }

    fn has_undecoded(packet: &Self::Packet) -> bool {
        packet.has_undecoded()
    }

    fn take_undecoded(packet: &mut Self::Packet) -> Self::Packet {
        ipfix::Packet {
            header: packet.header.clone(),
            sets: packet
                .sets
                .extract_if(.., |set| matches!(set, ipfix::Set::Undecoded { .. }))
                .collect(),
        }
    }
}

impl<P: TemplatedParser> State<P> {
    fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            parser: P::new(registry, timeout),
            converter: templated::Converter::default(),
            held: Held::default(),
        }
    }

    /// Converts what `packet` has templates for, adding the records to
    /// `records`; the sets that still lack one, if any.
    fn convert(
        &mut self,
        mut packet: P::Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) -> Option<P::Packet> {
        let undecoded = P::has_undecoded(&packet).then(|| P::take_undecoded(&mut packet));
        self.converter.convert(packet, received, records);
        undecoded
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

    /// Holds the NetFlow v9 and IPFIX data sets whose template has not
    /// come, within `limits` for each protocol of a session, and converts
    /// them once a later datagram of their session brings templates, before
    /// that datagram's own records. Their records keep the receive time of
    /// the datagram they came in. The other sets of a datagram are
    /// converted at once, and a datagram held through template arrivals
    /// that are not its own does not get younger.
    ///
    /// A template ID an exporter reuses for another template within
    /// `max_age` decodes the sets held for the old one wrongly (RFC 7011
    /// section 9); a short `max_age` keeps that window small.
    pub fn with_pending(mut self, limits: PendingLimits) -> Self {
        self.pending = Some(limits);
        self
    }

    /// What is held for templates not received yet; `None` unless
    /// [`Collector::with_pending`] set limits.
    pub fn pending(&self) -> Option<PendingStats> {
        self.pending.map(|_| PendingStats {
            held_bytes: self.sessions.values().map(Session::held_bytes).sum(),
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
                    &mut session.netflow_v9
                })?;
            }
            Protocol::Ipfix => {
                self.collect_templated(received, datagram, records, |session| &mut session.ipfix)?;
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
    /// state, `state_of` the session, with the sets held for templates it
    /// brings converted first.
    fn collect_templated<P: TemplatedParser>(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
        state_of: impl Fn(&mut Session) -> &mut Option<State<P>>,
    ) -> Result<(), ParseError> {
        let (registry, timeout, limits) = (self.registry.clone(), self.timeout, self.pending);
        let Some(session) = self.session(received.exporter) else {
            return Ok(());
        };
        let state = state_of(session).get_or_insert_with(|| State::new(registry, timeout));
        let mut dropped = 0;
        let mut packet = state.parser.parse(datagram)?;
        if P::has_templates(&packet) {
            if let Some(limits) = limits {
                let (taken, aged) = state.held.take(limits);
                dropped += aged;
                for held in taken {
                    let still_held = held.retry(|mut packet, received| {
                        state.parser.resolve(&mut packet);
                        state.convert(packet, received, records)
                    });
                    if let Some(held) = still_held {
                        state.held.keep(held);
                    }
                }
            }
            // The template came after the data in the same datagram.
            if P::has_undecoded(&packet) {
                state.parser.resolve(&mut packet);
            }
        }
        if let Some(undecoded) = state.convert(packet, &received, records)
            && let Some(limits) = limits
        {
            dropped += state.held.push(limits, received, undecoded, datagram.len());
        }
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
            self.sessions.retain(|_, session| {
                let alive = session.last_seen.is_some_and(|seen| now - seen < timeout);
                if !alive {
                    self.dropped += session.held_datagrams();
                }
                alive
            });
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

impl Session {
    fn held_bytes(&self) -> usize {
        self.netflow_v9
            .as_ref()
            .map_or(0, |state| state.held.bytes())
            + self.ipfix.as_ref().map_or(0, |state| state.held.bytes())
    }

    fn held_datagrams(&self) -> u64 {
        (self.netflow_v9.as_ref().map_or(0, |state| state.held.len())
            + self.ipfix.as_ref().map_or(0, |state| state.held.len())) as u64
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

    fn template(set_id: u16, template_id: u16, element: u16) -> Vec<u8> {
        set(set_id, &words(&[template_id, 1, element, 4]))
    }

    fn octets(records: &[Record]) -> Vec<u64> {
        records
            .iter()
            .map(|record| {
                record
                    .first(iana::OCTET_DELTA_COUNT)
                    .unwrap()
                    .as_u64()
                    .unwrap()
            })
            .collect()
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
    fn retrying_a_mixed_packet_does_not_repeat_already_decoded_records() {
        for (packet, template_set) in [
            (ipfix as fn(u32, &[Vec<u8>]) -> Vec<u8>, 2),
            (netflow_v9, 0),
        ] {
            let mut collector = holding();
            collect(
                &mut collector,
                100,
                &packet(1, &[octet_count_template(template_set)]),
            );
            let records = collect(
                &mut collector,
                101,
                &packet(
                    2,
                    &[
                        octet_count_data(5),
                        set(257, &6u32.to_be_bytes()),
                        set(258, &7u32.to_be_bytes()),
                    ],
                ),
            );
            assert_eq!(octets(&records), [5]);

            // Release each missing set independently, without repeating 5 or 6.
            for (id, expected) in [(257, 6), (258, 7)] {
                let records = collect(
                    &mut collector,
                    102,
                    &packet(3, &[template(template_set, id, iana::OCTET_DELTA_COUNT.id)]),
                );
                assert_eq!(octets(&records), [expected]);
                assert_eq!(records[0].sequence_number, 2);
                assert_eq!(
                    records[0].first(iana::COLLECTION_TIME_MILLISECONDS),
                    Some(&Value::DateTimeMilliseconds(101_000))
                );
            }
            assert_eq!(collector.pending().unwrap().held_bytes, 0);
        }
    }

    #[test]
    fn pending_datagrams_of_other_protocols_survive_a_template_arrival() {
        let mut collector = holding();
        collect(&mut collector, 100, &ipfix(1, &[octet_count_data(5)]));
        collect(&mut collector, 101, &netflow_v9(2, &[octet_count_data(6)]));

        let records = collect(&mut collector, 102, &ipfix(3, &[octet_count_template(2)]));
        assert_eq!(octets(&records), [5]);
        assert_eq!(records[0].protocol, Protocol::Ipfix);
        assert_eq!(collector.pending().unwrap().dropped_datagrams, 0);

        let records = collect(
            &mut collector,
            103,
            &netflow_v9(4, &[octet_count_template(0)]),
        );
        assert_eq!(octets(&records), [6]);
        assert_eq!(records[0].protocol, Protocol::NetflowV9);
        assert_eq!(collector.pending().unwrap().held_bytes, 0);
    }

    #[test]
    fn resolving_missing_sets_does_not_reinterpret_known_sets() {
        for (packet, template_set) in [
            (ipfix as fn(u32, &[Vec<u8>]) -> Vec<u8>, 2),
            (netflow_v9, 0),
        ] {
            let mut collector = holding();
            collect(
                &mut collector,
                100,
                &packet(1, &[octet_count_template(template_set)]),
            );
            let records = collect(
                &mut collector,
                101,
                &packet(
                    2,
                    &[
                        octet_count_data(5),
                        set(257, &6u32.to_be_bytes()),
                        template(template_set, 256, iana::PACKET_DELTA_COUNT.id),
                        template(template_set, 257, iana::OCTET_DELTA_COUNT.id),
                    ],
                ),
            );
            // Set 256 was already decoded using the definition preceding it.
            assert_eq!(octets(&records), [5, 6]);
        }
    }

    #[test]
    fn retrying_pending_data_does_not_restore_an_old_template() {
        for (packet, template_set) in [
            (ipfix as fn(u32, &[Vec<u8>]) -> Vec<u8>, 2),
            (netflow_v9, 0),
        ] {
            let mut collector = holding();
            collect(
                &mut collector,
                100,
                &packet(
                    1,
                    &[
                        octet_count_template(template_set),
                        set(257, &6u32.to_be_bytes()),
                    ],
                ),
            );
            collect(
                &mut collector,
                101,
                &packet(
                    2,
                    &[
                        template(template_set, 256, iana::PACKET_DELTA_COUNT.id),
                        template(template_set, 257, iana::OCTET_DELTA_COUNT.id),
                    ],
                ),
            );
            let records = collect(&mut collector, 102, &packet(3, &[octet_count_data(7)]));
            assert_eq!(
                records[0].first(iana::PACKET_DELTA_COUNT),
                Some(&Value::Unsigned32(7))
            );
            assert_eq!(records[0].first(iana::OCTET_DELTA_COUNT), None);
        }
    }

    #[test]
    fn pending_templates_are_scoped_by_exporter_port_and_domain() {
        let mut collector = holding();
        let mut other_port = received(100);
        other_port.exporter.set_port(2056);
        let mut other_domain = ipfix(2, &[octet_count_data(6)]);
        other_domain[12..16].copy_from_slice(&8u32.to_be_bytes());

        collect(&mut collector, 100, &ipfix(1, &[octet_count_data(5)]));
        collector
            .collect(
                other_port,
                &ipfix(3, &[octet_count_data(7)]),
                &mut Vec::new(),
            )
            .unwrap();
        collect(&mut collector, 100, &other_domain);
        let records = collect(&mut collector, 101, &ipfix(4, &[octet_count_template(2)]));
        assert_eq!(octets(&records), [5]);

        let mut template = ipfix(5, &[octet_count_template(2)]);
        template[12..16].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(octets(&collect(&mut collector, 102, &template)), [6]);
        let mut records = Vec::new();
        collector
            .collect(
                other_port,
                &ipfix(6, &[octet_count_template(2)]),
                &mut records,
            )
            .unwrap();
        assert_eq!(octets(&records), [7]);
        assert_eq!(
            records[0].first(iana::EXPORTER_TRANSPORT_PORT),
            Some(&Value::Unsigned16(2056))
        );
        assert_eq!(collector.pending().unwrap(), PendingStats::default());
    }

    #[test]
    fn each_protocol_of_a_session_has_the_pending_budget() {
        let v9 = netflow_v9(2, &[octet_count_data(6)]);
        let ipfix_data = ipfix(1, &[octet_count_data(5)]);
        let mut collector = Collector::of(Family::Netflow).with_pending(PendingLimits {
            session_bytes: v9.len(),
            max_age: Duration::from_mins(1),
        });
        collect(&mut collector, 100, &ipfix_data);
        collect(&mut collector, 101, &v9);
        assert_eq!(
            collector.pending().unwrap(),
            PendingStats {
                held_bytes: ipfix_data.len() + v9.len(),
                dropped_datagrams: 0,
            }
        );
        assert_eq!(
            octets(&collect(
                &mut collector,
                102,
                &ipfix(3, &[octet_count_template(2)])
            )),
            [5]
        );
        assert_eq!(
            octets(&collect(
                &mut collector,
                103,
                &netflow_v9(4, &[octet_count_template(0)])
            )),
            [6]
        );
        assert_eq!(collector.pending().unwrap().held_bytes, 0);
    }

    #[test]
    fn refusing_pending_data_still_emits_the_known_records() {
        let mut collector = Collector::of(Family::Netflow).with_pending(PendingLimits {
            session_bytes: 0,
            max_age: Duration::from_mins(1),
        });
        let records = collect(
            &mut collector,
            100,
            &ipfix(
                1,
                &[
                    octet_count_template(2),
                    octet_count_data(5),
                    set(257, &6u32.to_be_bytes()),
                ],
            ),
        );
        assert_eq!(octets(&records), [5]);
        assert_eq!(
            collector.pending().unwrap(),
            PendingStats {
                held_bytes: 0,
                dropped_datagrams: 1,
            }
        );
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
        assert_eq!(collector.pending().unwrap().dropped_datagrams, 1);
    }
}
