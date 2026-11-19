use std::time::{Duration, Instant};

use super::sampling::SamplingParams;
use crate::information_element::ElementId;
use crate::timed_map::BoundedTimedMap;
use crate::value::Value;

/// What a sampling rate applies to, within an observation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Scope {
    /// The whole domain.
    Domain,
    /// The data records naming this sampler or selector.
    Sampler(u64),
    /// The data records naming no sampler: the rate of every sampler, if
    /// they agree.
    AnySampler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rate {
    OneIn(u32),
    Conflicting,
}

#[derive(Debug)]
pub struct ExporterOptions {
    sampling_rates: BoundedTimedMap<(u32, Scope), Rate>,
    system_init_ms: BoundedTimedMap<u32, u64>,
}

impl ExporterOptions {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            sampling_rates: BoundedTimedMap::new(capacity, ttl),
            system_init_ms: BoundedTimedMap::new(capacity, ttl),
        }
    }

    pub(super) fn learn<'v>(
        &mut self,
        domain: u32,
        fields: impl IntoIterator<Item = (ElementId, &'v Value)>,
        now: Instant,
    ) {
        let mut params = SamplingParams::default();
        for (id, value) in fields {
            params.observe(id, value);
            if id == ElementId::SYSTEM_INIT_TIME_MILLISECONDS
                && let Value::DateTimeMilliseconds(millis) = *value
            {
                self.system_init_ms.insert_at(domain, millis, now);
            }
        }
        self.learn_sampling_rate(domain, &params, now);
    }

    fn learn_sampling_rate(&mut self, domain: u32, params: &SamplingParams, now: Instant) {
        let Some(rate) = params.rate() else {
            return;
        };
        let rates = &mut self.sampling_rates;
        let Some(sampler) = params.sampler() else {
            rates.insert_at((domain, Scope::Domain), Rate::OneIn(rate), now);
            return;
        };
        rates.insert_at((domain, Scope::Sampler(sampler)), Rate::OneIn(rate), now);

        let any = match rates.get_at(&(domain, Scope::AnySampler), now) {
            // Not refreshed, so the conflict ends once the sampler that
            // caused it stops being stated.
            Some(Rate::Conflicting) => return,
            Some(&Rate::OneIn(known)) if known != rate => Rate::Conflicting,
            _ => Rate::OneIn(rate),
        };
        rates.insert_at((domain, Scope::AnySampler), any, now);
    }

    pub(super) fn sampling_rate(
        &self,
        domain: u32,
        sampler: Option<u64>,
        now: Instant,
    ) -> Option<u32> {
        let get = |scope| match self.sampling_rates.get_at(&(domain, scope), now) {
            Some(&Rate::OneIn(rate)) => Some(rate),
            _ => None,
        };
        sampler
            .and_then(|sampler| get(Scope::Sampler(sampler)))
            .or_else(|| get(Scope::Domain))
            .or_else(|| get(Scope::AnySampler))
    }

    pub(super) fn system_init_ms(&self, domain: u32, now: Instant) -> Option<u64> {
        self.system_init_ms.get_at(&domain, now).copied()
    }
}
