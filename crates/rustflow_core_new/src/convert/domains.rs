//! What an exporter's options records said, per observation domain.

use std::collections::HashMap;

use crate::convert::Record;
use crate::convert::sampling::{Sampling, SamplingOptions};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::value::Value;

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
pub(crate) struct Domains(HashMap<u32, Domain>);

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
    scoped_sampling: HashMap<SamplingKey, Sampling>,
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
            elements: Arc::from(elements),
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
