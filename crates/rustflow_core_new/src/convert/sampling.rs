//! How packets were sampled, as the Packet Sampling (PSAMP) elements
//! IANA's registry describes a Selector by (RFC 5477), and as options
//! records state it.

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
