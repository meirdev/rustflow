//! How packets were sampled: as the Packet Sampling (PSAMP) elements
//! IANA's registry describes a Selector by (RFC 5477), as options records
//! state it, and as an exporter's options records are kept per observation
//! domain, with what else they said of it.

use rustc_hash::FxHashMap;

use crate::convert::Record;
use crate::convert::record::Fields;
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::value::Value;

/// IANA's PSAMP selector algorithm numbers.
const SYSTEMATIC_COUNT_BASED: u16 = 1;
const RANDOM_N_OUT_OF_N: u16 = 3;

/// One packet in every `rate` sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sampling {
    pub(crate) rate: u32,
    /// `None` when the exporter does not say how it chose the packets.
    pub(crate) method: Option<Method>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    /// Every `rate`th packet.
    Systematic,
    /// One packet out of every `rate`, chosen at random.
    Random,
}

impl Sampling {
    /// Random sampling is one packet out of a population of `rate`
    /// (samplingSize and samplingPopulation). Systematic sampling, or
    /// sampling by a method not given, is one packet then `rate - 1`
    /// skipped (samplingPacketInterval and samplingPacketSpace), without a
    /// selector algorithm to claim a method for the latter.
    pub(crate) fn add_to(self, fields: &mut Fields) {
        self.for_each(|element, value| fields.push(element, value));
    }

    /// Gives `push` each field, in record order.
    pub(crate) fn for_each(self, mut push: impl FnMut(ElementId, Value)) {
        if self.method == Some(Method::Random) {
            push(
                iana::SELECTOR_ALGORITHM,
                Value::Unsigned16(RANDOM_N_OUT_OF_N),
            );
            push(iana::SAMPLING_SIZE, Value::Unsigned32(1));
            push(iana::SAMPLING_POPULATION, Value::Unsigned32(self.rate));
            return;
        }
        if self.method == Some(Method::Systematic) {
            push(
                iana::SELECTOR_ALGORITHM,
                Value::Unsigned16(SYSTEMATIC_COUNT_BASED),
            );
        }
        push(iana::SAMPLING_PACKET_INTERVAL, Value::Unsigned32(1));
        push(
            iana::SAMPLING_PACKET_SPACE,
            Value::Unsigned32(self.rate.saturating_sub(1)),
        );
    }
}

/// What an options record says of sampling, gathered field by field.
#[derive(Debug, Default)]
pub(crate) struct SamplingOptions {
    rate: Option<u32>,
    packet_interval: Option<u32>,
    packet_space: Option<u32>,
    size: Option<u32>,
    population: Option<u32>,
    method: Option<Method>,
}

impl SamplingOptions {
    /// The elements [`observe`](Self::observe) reads.
    pub(crate) const ELEMENTS: [ElementId; 9] = [
        iana::SAMPLING_INTERVAL,
        iana::SAMPLER_RANDOM_INTERVAL,
        iana::SAMPLING_PACKET_INTERVAL,
        iana::SAMPLING_PACKET_SPACE,
        iana::SAMPLING_SIZE,
        iana::SAMPLING_POPULATION,
        iana::SAMPLING_ALGORITHM,
        iana::SAMPLER_MODE,
        iana::SELECTOR_ALGORITHM,
    ];

    pub(crate) fn observe(&mut self, element: ElementId, value: &Value) {
        let number = || value.as_u64().and_then(|v| u32::try_from(v).ok());
        match element {
            iana::SAMPLING_INTERVAL => self.rate = self.rate.or(number()),
            iana::SAMPLER_RANDOM_INTERVAL => {
                self.rate = self.rate.or(number());
                self.method = Some(Method::Random);
            }
            iana::SAMPLING_PACKET_INTERVAL => self.packet_interval = number(),
            iana::SAMPLING_PACKET_SPACE => self.packet_space = number(),
            iana::SAMPLING_SIZE => self.size = number(),
            iana::SAMPLING_POPULATION => self.population = number(),
            // NetFlow's deterministic sampling is PSAMP's systematic
            // count-based; the numbers differ for random sampling.
            iana::SAMPLING_ALGORITHM | iana::SAMPLER_MODE => {
                self.method = match number() {
                    Some(1) => Some(Method::Systematic),
                    Some(2) => Some(Method::Random),
                    _ => self.method,
                };
            }
            iana::SELECTOR_ALGORITHM => {
                self.method = match number() {
                    Some(1) => Some(Method::Systematic),
                    Some(3) => Some(Method::Random),
                    _ => self.method,
                };
            }
            _ => {}
        }
    }

    /// The 1-in-N rate, by the method stated. `samplingInterval` and
    /// `samplerRandomInterval` give the rate; the PSAMP pairs select
    /// `samplingPacketInterval` packets out of every
    /// `samplingPacketInterval + samplingPacketSpace`, and `samplingSize` out
    /// of every `samplingPopulation`, which is a rate only when that is a
    /// whole 1 in N. A `samplingPacketInterval` on its own is read as the rate,
    /// which is how many exporters use it.
    pub(crate) fn sampling(&self) -> Option<Sampling> {
        let rate = self
            .rate
            .or_else(|| match (self.size, self.population) {
                (Some(size), Some(population)) => whole_ratio(size, u64::from(population)),
                _ => None,
            })
            .or_else(|| match (self.packet_interval, self.packet_space) {
                (Some(interval), Some(space)) => {
                    whole_ratio(interval, u64::from(interval) + u64::from(space))
                }
                (interval, _) => interval,
            })?;
        let method = self.method.or_else(|| {
            (self.rate.is_none() && self.size.is_some() && self.population.is_some())
                .then_some(Method::Random)
        });
        Some(Sampling { rate, method })
    }
}

/// `whole / part` when it is a whole number.
fn whole_ratio(part: u32, whole: u64) -> Option<u32> {
    let part = u64::from(part);
    if part == 0 || !whole.is_multiple_of(part) {
        return None;
    }
    u32::try_from(whole / part).ok()
}

/// Observation domains one exporter may have state for; it decides how
/// many it names.
const MAX_DOMAINS: usize = 1024;

/// Scoped samplings one domain may have, and options records of distinct
/// kinds it may keep; the exporter decides how many it sends.
const MAX_SAMPLERS: usize = 1024;
const MAX_OPTIONS: usize = 1024;

/// What a sampling can be scoped to: a sampler or selector, the interface a
/// packet came in or went out on, or a line card, by the element naming it
/// and its value.
pub(crate) type SamplingKey = (ElementId, u64);

/// The elements a sampling is scoped by, in the order a data record's are
/// tried. A sampler and a selector share one key, [`iana::SAMPLER_ID`].
pub(crate) const SAMPLING_KEYS: [ElementId; 4] = [
    iana::SAMPLER_ID,
    iana::INGRESS_INTERFACE,
    iana::EGRESS_INTERFACE,
    iana::LINE_CARD_ID,
];

/// The key `element` stands for, if it keys sampling at all.
pub(crate) fn sampling_key(element: ElementId) -> Option<ElementId> {
    match element {
        iana::SELECTOR_ID => Some(iana::SAMPLER_ID),
        element if SAMPLING_KEYS.contains(&element) => Some(element),
        _ => None,
    }
}

#[derive(Default)]
pub(crate) struct Domains(FxHashMap<u32, Domain>);

impl Domains {
    pub(crate) fn get(&self, domain: u32) -> Option<&Domain> {
        self.0.get(&domain)
    }

    /// The latest options record of each kind, by domain.
    pub(crate) fn options(&self) -> impl Iterator<Item = (u32, &Record)> {
        self.0
            .iter()
            .flat_map(|(&domain, known)| known.options.iter().map(move |record| (domain, record)))
    }

    /// Learns from a converted options record of `domain`, unless the
    /// exporter has named [`MAX_DOMAINS`] others already.
    pub(crate) fn learn(&mut self, domain: u32, record: &Record) {
        let full = self.0.len() >= MAX_DOMAINS;
        let domain = match self.0.get_mut(&domain) {
            Some(known) => known,
            None if full => return,
            None => self.0.entry(domain).or_default(),
        };
        domain.learn(record);
    }
}

/// What the options records of one observation domain (source ID in v9)
/// said.
#[derive(Debug, Default)]
pub(crate) struct Domain {
    /// From options records scoped to the whole domain.
    sampling: Option<Sampling>,
    /// From options records scoped to a sampler, an interface or a line
    /// card, for the data records naming the same one.
    scoped_sampling: FxHashMap<SamplingKey, Sampling>,
    /// The sampling all of `scoped_sampling` share, if they agree.
    shared_scoped_sampling: Option<Sampling>,
    pub(crate) system_init_time_ms: Option<u64>,
    /// The latest options record of each kind: of each scope and set of
    /// elements.
    options: Vec<Record>,
}

impl Domain {
    fn learn(&mut self, record: &Record) {
        let mut options = SamplingOptions::default();
        for (element, value) in record.scope_elements().chain(record.iter()) {
            options.observe(element, value);
            if element == iana::SYSTEM_INIT_TIME_MILLISECONDS
                && let Value::DateTimeMilliseconds(millis) = value
            {
                self.system_init_time_ms = Some(*millis);
            }
        }
        if let Some(sampling) = options.sampling() {
            match scoped_to(record) {
                Some(key) => self.set_scoped_sampling(key, sampling),
                None => self.sampling = Some(sampling),
            }
        }
        self.keep(record);
    }

    fn keep(&mut self, record: &Record) {
        let same_kind = self
            .options
            .iter()
            .position(|known| known.scope == record.scope && known.elements == record.elements);
        match same_kind {
            Some(index) => self.options[index] = record.clone(),
            None if self.options.len() < MAX_OPTIONS => self.options.push(record.clone()),
            None => {}
        }
    }

    fn set_scoped_sampling(&mut self, key: SamplingKey, sampling: Sampling) {
        if self.scoped_sampling.len() < MAX_SAMPLERS {
            self.scoped_sampling.insert(key, sampling);
        } else if let Some(known) = self.scoped_sampling.get_mut(&key) {
            *known = sampling;
        }
        let mut samplings = self.scoped_sampling.values();
        self.shared_scoped_sampling = samplings
            .next()
            .copied()
            .filter(|first| samplings.all(|sampling| sampling == first));
    }

    /// The sampling of a data record carrying `keys`, tried in turn: the
    /// one scoped to the first with one, or else the domain's. A record
    /// that matches none, in a domain without sampling of its own, takes
    /// the scoped samplings when they agree: many exporters name the
    /// sampler or interface only in the options record.
    pub(crate) fn sampling_for(
        &self,
        keys: impl IntoIterator<Item = SamplingKey>,
    ) -> Option<Sampling> {
        if self.scoped_sampling.is_empty() {
            return self.sampling;
        }
        keys.into_iter()
            .find_map(|key| self.scoped_sampling.get(&key).copied())
            .or(self.sampling)
            .or(self.shared_scoped_sampling)
    }
}

/// What the sampling an options record states is scoped to; `None` for
/// the whole domain. A sampler named anywhere in the record keys it, since
/// many exporters name the sampler among the option fields rather than in
/// the scope; otherwise an interface or a line card in the scope does.
fn scoped_to(record: &Record) -> Option<SamplingKey> {
    let sampler = record
        .scope_elements()
        .chain(record.iter())
        .find(|(element, _)| sampling_key(*element) == Some(iana::SAMPLER_ID))
        .map(|(_, value)| (iana::SAMPLER_ID, value));
    let scoped = record
        .scope_elements()
        .find(|(element, _)| sampling_key(*element).is_some());
    let (key, value) = sampler.or(scoped)?;
    Some((key, value.as_u64()?))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::convert::Received;

    fn added(sampling: Sampling) -> Vec<(ElementId, Value)> {
        let received = Received {
            exporter: SocketAddr::from((Ipv4Addr::LOCALHOST, 2055)),
            time: None,
        };
        let mut additions = Fields::additions(&received, None);
        sampling.add_to(&mut additions);
        additions
            .elements
            .into_iter()
            .zip(additions.values)
            .skip(2)
            .collect()
    }

    fn options(fields: &[(ElementId, u32)]) -> Option<Sampling> {
        let mut options = SamplingOptions::default();
        for &(element, value) in fields {
            options.observe(element, &Value::Unsigned32(value));
        }
        options.sampling()
    }

    #[test]
    fn one_in_n_is_written_as_its_method_takes_it() {
        let sampling = |method| Sampling { rate: 100, method };
        assert_eq!(
            added(sampling(None)),
            [
                (iana::SAMPLING_PACKET_INTERVAL, Value::Unsigned32(1)),
                (iana::SAMPLING_PACKET_SPACE, Value::Unsigned32(99)),
            ]
        );
        assert_eq!(
            added(sampling(Some(Method::Systematic)))[0],
            (iana::SELECTOR_ALGORITHM, Value::Unsigned16(1))
        );
        assert_eq!(
            added(sampling(Some(Method::Random))),
            [
                (iana::SELECTOR_ALGORITHM, Value::Unsigned16(3)),
                (iana::SAMPLING_SIZE, Value::Unsigned32(1)),
                (iana::SAMPLING_POPULATION, Value::Unsigned32(100)),
            ]
        );
    }

    #[test]
    fn options_records_state_a_rate_and_a_method() {
        let sampling = |rate, method| Some(Sampling { rate, method });
        assert_eq!(
            options(&[(iana::SAMPLING_INTERVAL, 100)]),
            sampling(100, None)
        );
        assert_eq!(
            options(&[
                (iana::SAMPLING_INTERVAL, 100),
                (iana::SAMPLING_ALGORITHM, 2)
            ]),
            sampling(100, Some(Method::Random))
        );
        assert_eq!(
            options(&[(iana::SAMPLER_RANDOM_INTERVAL, 50)]),
            sampling(50, Some(Method::Random))
        );
        assert_eq!(
            options(&[(iana::SAMPLER_MODE, 1), (iana::SAMPLING_INTERVAL, 10)]),
            sampling(10, Some(Method::Systematic))
        );
        assert_eq!(
            options(&[
                (iana::SELECTOR_ALGORITHM, 1),
                (iana::SAMPLING_PACKET_INTERVAL, 1),
                (iana::SAMPLING_PACKET_SPACE, 99),
            ]),
            sampling(100, Some(Method::Systematic))
        );
        assert_eq!(
            options(&[(iana::SAMPLING_SIZE, 2), (iana::SAMPLING_POPULATION, 200)]),
            sampling(100, Some(Method::Random))
        );
        assert_eq!(
            options(&[(iana::SAMPLING_PACKET_INTERVAL, 64)]),
            sampling(64, None)
        );
    }

    #[test]
    fn a_ratio_that_is_not_one_in_n_states_no_rate() {
        assert_eq!(
            options(&[
                (iana::SAMPLING_PACKET_INTERVAL, 3),
                (iana::SAMPLING_PACKET_SPACE, 5),
            ]),
            None
        );
        assert_eq!(
            options(&[(iana::SAMPLING_SIZE, 0), (iana::SAMPLING_POPULATION, 10)]),
            None
        );
        assert_eq!(options(&[(iana::SELECTOR_ALGORITHM, 3)]), None);
    }
}

#[cfg(test)]
mod domain_tests {
    use std::sync::Arc;

    use super::*;
    use crate::convert::sampling::Method;
    use crate::convert::{Protocol, Scope};
    use crate::protocol::information_element::ElementId;

    fn learn(domains: &mut Domains, domain: u32, fields: &[(ElementId, Value)]) {
        let scope = (iana::OBSERVATION_DOMAIN_ID, Value::Unsigned32(domain));
        learn_scoped(domains, domain, scope, fields);
    }

    fn learn_scoped(
        domains: &mut Domains,
        domain: u32,
        (scope, value): (ElementId, Value),
        fields: &[(ElementId, Value)],
    ) {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        let record = Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: vec![(Scope::Element(scope), value)],
            elements: Arc::new(elements.into()),
            values,
        };
        domains.learn(domain, &record);
    }

    #[test]
    fn interface_sampling_applies_to_that_interfaces_records_alone() {
        let mut domains = Domains::default();
        for (interface, rate) in [(1, 10), (2, 20)] {
            learn_scoped(
                &mut domains,
                7,
                (iana::INGRESS_INTERFACE, Value::Unsigned32(interface)),
                &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(rate))],
            );
        }
        let domain = domains.get(7).unwrap();
        assert_eq!(
            domain.sampling_for([(iana::INGRESS_INTERFACE, 2)]),
            one_in(20)
        );
        assert_eq!(domain.sampling_for([(iana::INGRESS_INTERFACE, 3)]), None);
        assert_eq!(domain.sampling_for([]), None);
    }

    #[test]
    fn sampling_under_any_other_scope_is_the_domains() {
        let mut domains = Domains::default();
        learn_scoped(
            &mut domains,
            7,
            (iana::TEMPLATE_ID, Value::Unsigned16(256)),
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(10))],
        );
        assert_eq!(domains.get(7).unwrap().sampling_for([]), one_in(10));
    }

    fn one_in(rate: u32) -> Option<Sampling> {
        Some(Sampling { rate, method: None })
    }

    #[test]
    fn records_take_their_samplers_rate_or_else_the_domains() {
        let mut domains = Domains::default();
        let sampler = |id: u8, rate: u32| {
            [
                (iana::SAMPLER_ID, Value::Unsigned8(id)),
                (iana::SAMPLING_INTERVAL, Value::Unsigned32(rate)),
            ]
        };
        learn(&mut domains, 7, &sampler(1, 10));
        learn(&mut domains, 7, &sampler(2, 20));
        let domain = domains.get(7).unwrap();

        assert_eq!(domain.sampling_for([(iana::SAMPLER_ID, 2)]), one_in(20));
        assert_eq!(domain.sampling_for([]), None);

        learn(
            &mut domains,
            7,
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(5))],
        );
        let domain = domains.get(7).unwrap();
        assert_eq!(domain.sampling_for([]), one_in(5));
        assert_eq!(domain.sampling_for([(iana::SAMPLER_ID, 9)]), one_in(5));
    }

    #[test]
    fn records_naming_no_sampler_take_the_samplers_when_they_agree() {
        let mut domains = Domains::default();
        for id in 1..=2 {
            learn(
                &mut domains,
                7,
                &[
                    (iana::SELECTOR_ID, Value::Unsigned64(id)),
                    (iana::SAMPLER_RANDOM_INTERVAL, Value::Unsigned32(100)),
                ],
            );
        }
        assert_eq!(
            domains.get(7).unwrap().sampling_for([]),
            Some(Sampling {
                rate: 100,
                method: Some(Method::Random),
            })
        );
    }

    #[test]
    fn the_latest_options_record_of_each_kind_is_kept() {
        let mut domains = Domains::default();
        learn(
            &mut domains,
            7,
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(10))],
        );
        learn(
            &mut domains,
            7,
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(20))],
        );
        learn(
            &mut domains,
            7,
            &[(iana::EXPORTED_MESSAGE_TOTAL_COUNT, Value::Unsigned64(5))],
        );
        let kept: Vec<_> = domains
            .options()
            .map(|(domain, record)| (domain, record.values.clone()))
            .collect();
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&(7, vec![Value::Unsigned32(20)])));
        assert!(kept.contains(&(7, vec![Value::Unsigned64(5)])));
    }

    #[test]
    fn the_system_init_time_is_learned() {
        let mut domains = Domains::default();
        learn(
            &mut domains,
            7,
            &[(
                iana::SYSTEM_INIT_TIME_MILLISECONDS,
                Value::DateTimeMilliseconds(1_000),
            )],
        );
        assert_eq!(domains.get(7).unwrap().system_init_time_ms, Some(1_000));
        assert!(domains.get(8).is_none());
    }

    #[test]
    fn an_exporter_has_state_for_at_most_max_domains() {
        let mut domains = Domains::default();
        let interval = [(iana::SAMPLING_INTERVAL, Value::Unsigned32(10))];
        for domain in 0..=u32::try_from(MAX_DOMAINS).unwrap() {
            learn(&mut domains, domain, &interval);
        }
        assert!(domains.get(0).is_some());
        assert!(domains.get(u32::try_from(MAX_DOMAINS).unwrap()).is_none());
    }
}
