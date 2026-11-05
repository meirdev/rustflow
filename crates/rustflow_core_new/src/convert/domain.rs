//! What an exporter's options records said, per observation domain.

use std::collections::HashMap;

use crate::convert::Record;
use crate::convert::sampling::{Sampling, SamplingOptions};
use crate::protocol::information_element::iana;
use crate::protocol::value::Value;

/// Observation domains one exporter may have state for; it decides how
/// many it names.
const MAX_DOMAINS: usize = 1024;

/// Samplers one domain may have rates for, and options records of
/// distinct kinds it may keep; the exporter decides how many it sends.
const MAX_SAMPLERS: usize = 1024;
const MAX_OPTIONS: usize = 1024;

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
    /// From options records that name no sampler.
    sampling: Option<Sampling>,
    /// From options records that name a sampler (`samplerId` or
    /// `selectorId`), for the data records that name the same one.
    sampler_sampling: HashMap<u64, Sampling>,
    /// The sampling all of `sampler_sampling` share, if they agree.
    shared_sampler_sampling: Option<Sampling>,
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
            self.set_sampling(sampler_id(record), sampling);
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

    fn set_sampling(&mut self, sampler_id: Option<u64>, sampling: Sampling) {
        match sampler_id {
            None => self.sampling = Some(sampling),
            Some(id) if self.sampler_sampling.len() < MAX_SAMPLERS => {
                self.sampler_sampling.insert(id, sampling);
            }
            Some(id) => {
                if let Some(known) = self.sampler_sampling.get_mut(&id) {
                    *known = sampling;
                }
            }
        }
        let mut samplings = self.sampler_sampling.values();
        self.shared_sampler_sampling = samplings
            .next()
            .copied()
            .filter(|first| samplings.all(|sampling| sampling == first));
    }

    /// The sampling of a data record naming `sampler_id`: its sampler's,
    /// or else the domain's. A record that names no known sampler, in a
    /// domain without sampling of its own, takes the samplers' when they
    /// agree: many exporters name the sampler only in the options record.
    pub(crate) fn sampling_for(&self, sampler_id: Option<u64>) -> Option<Sampling> {
        if self.sampler_sampling.is_empty() {
            return self.sampling;
        }
        sampler_id
            .and_then(|id| self.sampler_sampling.get(&id).copied())
            .or(self.sampling)
            .or(self.shared_sampler_sampling)
    }
}

/// The sampler an options record names, in its scope or its fields.
fn sampler_id(record: &Record) -> Option<u64> {
    record
        .scope_elements()
        .chain(record.iter())
        .find(|(element, _)| matches!(*element, iana::SAMPLER_ID | iana::SELECTOR_ID))
        .and_then(|(_, value)| value.as_u64())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::convert::sampling::Method;
    use crate::convert::{Protocol, Scope};
    use crate::protocol::information_element::ElementId;

    fn learn(domains: &mut Domains, domain: u32, fields: &[(ElementId, Value)]) {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        let record = Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: vec![(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(domain),
            )],
            elements: Arc::from(elements),
            values,
        };
        domains.learn(domain, &record);
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

        assert_eq!(domain.sampling_for(Some(2)), one_in(20));
        assert_eq!(domain.sampling_for(None), None);

        learn(
            &mut domains,
            7,
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(5))],
        );
        let domain = domains.get(7).unwrap();
        assert_eq!(domain.sampling_for(None), one_in(5));
        assert_eq!(domain.sampling_for(Some(9)), one_in(5));
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
            domains.get(7).unwrap().sampling_for(None),
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
