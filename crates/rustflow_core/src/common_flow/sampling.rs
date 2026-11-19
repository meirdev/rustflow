use crate::information_element::ElementId;
use crate::value::Value;

#[derive(Debug, Default)]
pub(super) struct SamplingParams {
    rate: Option<u32>,
    packet_interval: Option<u32>,
    packet_space: Option<u32>,
    size: Option<u32>,
    population: Option<u32>,
    sampler: Option<u64>,
}

impl SamplingParams {
    pub(super) fn observe(&mut self, id: ElementId, value: &Value) {
        let number = || value.as_u64().and_then(|n| u32::try_from(n).ok());
        match id {
            ElementId::SAMPLING_INTERVAL | ElementId::SAMPLER_RANDOM_INTERVAL => {
                self.rate = number();
            }
            ElementId::SAMPLING_PACKET_INTERVAL => self.packet_interval = number(),
            ElementId::SAMPLING_PACKET_SPACE => self.packet_space = number(),
            ElementId::SAMPLING_SIZE => self.size = number(),
            ElementId::SAMPLING_POPULATION => self.population = number(),
            ElementId::SAMPLER_ID | ElementId::SELECTOR_ID => self.sampler = value.as_u64(),
            _ => {}
        }
    }

    pub(super) fn sampler(&self) -> Option<u64> {
        self.sampler
    }

    /// The 1-in-N rate. The PSAMP pairs (RFC 5477) select
    /// `samplingPacketInterval` packets out of every `samplingPacketInterval +
    /// samplingPacketSpace`, and `samplingSize` out of every
    /// `samplingPopulation`, which is a rate only when it is a whole 1 in N.
    /// A `samplingPacketInterval` on its own is read as the rate, which is
    /// how many exporters use it.
    pub(super) fn rate(&self) -> Option<u32> {
        self.rate
            .or_else(|| whole_ratio(self.size?, self.population?.into()))
            .or_else(|| match (self.packet_interval, self.packet_space) {
                (Some(interval), Some(space)) => {
                    whole_ratio(interval, u64::from(interval) + u64::from(space))
                }
                (interval, None) => interval,
                (None, Some(_)) => None,
            })
            .filter(|&rate| rate != 0)
    }
}

fn whole_ratio(part: u32, whole: u64) -> Option<u32> {
    let part = u64::from(part);
    if part == 0 || !whole.is_multiple_of(part) {
        return None;
    }
    u32::try_from(whole / part).ok()
}
