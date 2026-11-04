//! What an exporter's options records said, per observation domain.

use std::collections::HashMap;

use rustflow_protocol::information_element::iana;
use rustflow_protocol::value::Value;
use rustflow_protocol::{Elements, RecordRef};

use crate::sampling::{Sampling, SamplingOptions};

/// Observation domains one exporter may have state for; it decides how
/// many it names.
const MAX_DOMAINS: usize = 1024;

/// Samplers one domain may have rates for; the exporter decides how many it
/// names.
const MAX_SAMPLERS: usize = 1024;

#[derive(Default)]
pub(crate) struct Domains(HashMap<u32, Domain>);

impl Domains {
    pub(crate) fn get(&self, domain: u32) -> Option<&Domain> {
        self.0.get(&domain)
    }

    /// Learns from an options record of `domain`, unless the exporter has
    /// named [`MAX_DOMAINS`] others already.
    pub(crate) fn learn<T: Elements + ?Sized>(&mut self, domain: u32, record: RecordRef<'_, T>) {
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
}

impl Domain {
    fn learn<T: Elements + ?Sized>(&mut self, record: RecordRef<'_, T>) {
        let mut options = SamplingOptions::default();
        for (element, value) in record.iter() {
            let Some(element) = element else {
                continue;
            };
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

/// The sampler a record names.
fn sampler_id<T: Elements + ?Sized>(record: RecordRef<'_, T>) -> Option<u64> {
    record
        .iter()
        .find(|(element, _)| matches!(element, Some(iana::SAMPLER_ID | iana::SELECTOR_ID)))
        .and_then(|(_, value)| value.as_u64())
}

#[cfg(test)]
mod tests {
    use rustflow_protocol::information_element::ElementId;

    use super::*;
    use crate::sampling::Method;

    fn learn(domains: &mut Domains, domain: u32, fields: &[(ElementId, Value)]) {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        domains.learn(domain, RecordRef::new(&elements[..], &values));
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
