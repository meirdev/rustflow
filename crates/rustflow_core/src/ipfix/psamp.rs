//! PSAMP (RFC 5476) report interpretation.
//!
//! A PSAMP Device exports three kinds of Options Data Records that describe
//! how packets were selected (RFC 5476 section 6.5):
//!
//! - Selector Report Interpretation: scoped on `selectorId`, carries the
//!   `selectorAlgorithm` and its parameters.
//! - Selection Sequence Report Interpretation: scoped on
//!   `selectionSequenceId`, lists the `selectorId`s applied in order.
//! - Selection Sequence Statistics Report Interpretation: scoped on
//!   `selectionSequenceId`, carries packets observed/selected counters.
//!
//! [`PsampCache`] recognizes these records and answers queries such as the
//! effective sampling rate for the Selection Sequence a Packet Report
//! references via its `selectionSequenceId`.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::common::InformationElement;
use crate::common::timeout_map::TimeoutHashMap;
use crate::ipfix::parser::{DataRecord, FieldValue};

/// PSAMP selectorAlgorithm identifiers.
///
/// See: https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SelectorAlgorithm {
    SystematicCountBasedSampling,
    SystematicTimeBasedSampling,
    RandomNOutOfNSampling,
    UniformProbabilisticSampling,
    PropertyMatchFiltering,
    HashBasedFilteringBob,
    HashBasedFilteringIpsx,
    HashBasedFilteringCrc,
    Unassigned,
}

impl From<u16> for SelectorAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::SystematicCountBasedSampling,
            2 => Self::SystematicTimeBasedSampling,
            3 => Self::RandomNOutOfNSampling,
            4 => Self::UniformProbabilisticSampling,
            5 => Self::PropertyMatchFiltering,
            6 => Self::HashBasedFilteringBob,
            7 => Self::HashBasedFilteringIpsx,
            8 => Self::HashBasedFilteringCrc,
            _ => Self::Unassigned,
        }
    }
}

impl SelectorAlgorithm {
    pub fn is_filter(&self) -> bool {
        matches!(
            self,
            Self::PropertyMatchFiltering
                | Self::HashBasedFilteringBob
                | Self::HashBasedFilteringIpsx
                | Self::HashBasedFilteringCrc
        )
    }
}

/// A Primitive Selector's configuration, from a Selector Report
/// Interpretation (RFC 5476 section 6.5.2).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SelectorInfo {
    pub algorithm: u16,
    pub name: Option<String>,
    pub sampling_packet_interval: Option<u32>,
    pub sampling_packet_space: Option<u32>,
    pub sampling_time_interval: Option<u32>,
    pub sampling_time_space: Option<u32>,
    pub sampling_size: Option<u32>,
    pub sampling_population: Option<u32>,
    pub sampling_probability: Option<f64>,
    pub hash_ip_payload_offset: Option<u64>,
    pub hash_ip_payload_size: Option<u64>,
    pub hash_output_range: Option<(u64, u64)>,
    pub hash_selected_ranges: Vec<(u64, u64)>,
    pub hash_digest_output: Option<bool>,
    pub hash_initialiser_value: Option<u64>,
}

impl SelectorInfo {
    pub fn algorithm_kind(&self) -> SelectorAlgorithm {
        SelectorAlgorithm::from(self.algorithm)
    }

    /// Effective 1-in-N packet sampling rate configured for this selector,
    /// where that is well defined: count-based sampling selects `interval`
    /// packets out of every `interval + space`, n-out-of-N selects
    /// `size` out of `population`, and probabilistic sampling selects each
    /// packet with probability `p`. Time-based sampling and filters have no
    /// packet-count rate.
    pub fn sampling_rate(&self) -> Option<u32> {
        match self.algorithm_kind() {
            SelectorAlgorithm::SystematicCountBasedSampling => {
                let interval = u64::from(self.sampling_packet_interval?);
                let space = u64::from(self.sampling_packet_space?);
                (interval > 0).then(|| clamp_rate((interval + space) / interval))
            }
            SelectorAlgorithm::RandomNOutOfNSampling => {
                let size = u64::from(self.sampling_size?);
                let population = u64::from(self.sampling_population?);
                (size > 0).then(|| clamp_rate(population / size))
            }
            SelectorAlgorithm::UniformProbabilisticSampling => {
                let p = self.sampling_probability?;
                (p > 0.0 && p <= 1.0).then(|| clamp_rate((1.0 / p).round() as u64))
            }
            _ => None,
        }
    }
}

/// A Selection Sequence, from a Selection Sequence Report Interpretation
/// (RFC 5476 section 6.5.1): the Primitive Selectors applied in order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SelectionSequence {
    pub selector_ids: Vec<u64>,
}

/// Counters from a Selection Sequence Statistics Report Interpretation
/// (RFC 5476 section 6.5.3). `packets_selected` holds one counter per
/// selector in the sequence, in order; the last one is the number of packets
/// that made it through the whole sequence.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SelectionSequenceStats {
    pub packets_observed: u64,
    pub packets_selected: Vec<u64>,
}

/// Which kind of PSAMP report interpretation a record was recognized as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsampReportKind {
    Selector,
    SelectionSequence,
    SelectionSequenceStats,
}

/// Key: (exporter_address, observation_domain_id, selectorId or
/// selectionSequenceId)
pub type PsampKey = (IpAddr, u32, u64);

/// Cache of PSAMP report interpretations, keyed per exporter and observation
/// domain like [`crate::common::common_flow::SamplingRateCache`].
pub struct PsampCache {
    selectors: TimeoutHashMap<PsampKey, SelectorInfo>,
    sequences: TimeoutHashMap<PsampKey, SelectionSequence>,
    stats: TimeoutHashMap<PsampKey, SelectionSequenceStats>,
}

impl PsampCache {
    pub fn new(timeout: Duration) -> Self {
        Self {
            selectors: TimeoutHashMap::new(timeout),
            sequences: TimeoutHashMap::new(timeout),
            stats: TimeoutHashMap::new(timeout),
        }
    }

    pub fn selector(&self, key: &PsampKey) -> Option<&SelectorInfo> {
        self.selectors.get(key)
    }

    pub fn sequence(&self, key: &PsampKey) -> Option<&SelectionSequence> {
        self.sequences.get(key)
    }

    pub fn sequence_stats(&self, key: &PsampKey) -> Option<&SelectionSequenceStats> {
        self.stats.get(key)
    }

    pub fn cleanup(&mut self) {
        self.selectors.cleanup();
        self.sequences.cleanup();
        self.stats.cleanup();
    }

    /// Inspect an Options Data Record and absorb it if it is one of the PSAMP
    /// report interpretations. Returns what it was recognized as, or `None`
    /// for options data unrelated to PSAMP.
    pub fn update_from_options_data(
        &mut self,
        exporter: IpAddr,
        observation_domain_id: u32,
        record: &DataRecord,
    ) -> Option<PsampReportKind> {
        // Selector Report Interpretation: selectorId scope + selectorAlgorithm.
        if let Some(algorithm) = find_u64(record, InformationElement::SelectorAlgorithm)
            && let Some(selector_id) = find_u64(record, InformationElement::SelectorId)
        {
            let info = parse_selector_info(algorithm as u16, record);
            self.selectors
                .insert((exporter, observation_domain_id, selector_id), info);
            return Some(PsampReportKind::Selector);
        }

        let sequence_id = find_u64(record, InformationElement::SelectionSequenceId)?;
        let key = (exporter, observation_domain_id, sequence_id);

        // Selection Sequence Statistics Report Interpretation.
        let packets_selected = collect_u64(record, InformationElement::SelectorIdTotalPktsSelected);
        if !packets_selected.is_empty() {
            let packets_observed =
                find_u64(record, InformationElement::SelectorIdTotalPktsObserved)
                    .unwrap_or_default();
            self.stats.insert(
                key,
                SelectionSequenceStats {
                    packets_observed,
                    packets_selected,
                },
            );
            return Some(PsampReportKind::SelectionSequenceStats);
        }

        // Selection Sequence Report Interpretation.
        let selector_ids = collect_u64(record, InformationElement::SelectorId);
        if !selector_ids.is_empty() {
            self.sequences
                .insert(key, SelectionSequence { selector_ids });
            return Some(PsampReportKind::SelectionSequence);
        }

        None
    }

    /// Effective 1-in-N sampling rate for a Selection Sequence.
    ///
    /// Prefers the Attained Selection Fraction from the sequence statistics
    /// (packets observed / packets selected through the whole sequence);
    /// falls back to the configured rate, the product of the sampling rates
    /// of the samplers in the sequence (filters do not contribute a
    /// packet-count rate). Returns `None` when neither can be computed.
    pub fn sequence_sampling_rate(&self, key: &PsampKey) -> Option<u32> {
        if let Some(stats) = self.stats.get(key)
            && let Some(&selected) = stats.packets_selected.last()
            && selected > 0
            && stats.packets_observed > 0
        {
            return Some(clamp_rate(stats.packets_observed / selected));
        }

        let sequence = self.sequences.get(key)?;
        let mut rate = 1u64;

        for selector_id in &sequence.selector_ids {
            let selector = self.selectors.get(&(key.0, key.1, *selector_id))?;
            if !selector.algorithm_kind().is_filter() {
                rate = rate.saturating_mul(u64::from(selector.sampling_rate()?));
            }
        }

        Some(clamp_rate(rate))
    }
}

impl Default for PsampCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

fn clamp_rate(rate: u64) -> u32 {
    rate.clamp(1, u64::from(u32::MAX)) as u32
}

fn as_u64(value: &FieldValue) -> Option<u64> {
    match value {
        FieldValue::Unsigned8(v) => Some(u64::from(*v)),
        FieldValue::Unsigned16(v) => Some(u64::from(*v)),
        FieldValue::Unsigned32(v) => Some(u64::from(*v)),
        FieldValue::Unsigned64(v) => Some(*v),
        _ => None,
    }
}

fn as_u32(value: &FieldValue) -> Option<u32> {
    as_u64(value).map(|v| v.min(u64::from(u32::MAX)) as u32)
}

fn as_f64(value: &FieldValue) -> Option<f64> {
    match value {
        FieldValue::Float32(v) => Some(f64::from(*v)),
        FieldValue::Float64(v) => Some(*v),
        _ => None,
    }
}

fn matches_ie(record: &DataRecord, index: usize, ie: InformationElement) -> bool {
    let field = &record.0[index].0;
    field.enterprise_number.is_none() && field.information_element_identifier == u16::from(ie)
}

fn find_value(record: &DataRecord, ie: InformationElement) -> Option<&FieldValue> {
    record
        .0
        .iter()
        .find(|(field, _, _)| {
            field.enterprise_number.is_none()
                && field.information_element_identifier == u16::from(ie)
        })
        .map(|(_, _, value)| value)
}

fn find_u64(record: &DataRecord, ie: InformationElement) -> Option<u64> {
    find_value(record, ie).and_then(as_u64)
}

fn collect_u64(record: &DataRecord, ie: InformationElement) -> Vec<u64> {
    (0..record.0.len())
        .filter(|i| matches_ie(record, *i, ie))
        .filter_map(|i| as_u64(&record.0[i].2))
        .collect()
}

fn parse_selector_info(algorithm: u16, record: &DataRecord) -> SelectorInfo {
    use InformationElement as IE;

    let range_mins = collect_u64(record, IE::HashSelectedRangeMin);
    let range_maxes = collect_u64(record, IE::HashSelectedRangeMax);

    SelectorInfo {
        algorithm,
        name: find_value(record, IE::SelectorName).and_then(|v| match v {
            FieldValue::String(s) => Some(s.clone()),
            _ => None,
        }),
        sampling_packet_interval: find_value(record, IE::SamplingPacketInterval).and_then(as_u32),
        sampling_packet_space: find_value(record, IE::SamplingPacketSpace).and_then(as_u32),
        sampling_time_interval: find_value(record, IE::SamplingTimeInterval).and_then(as_u32),
        sampling_time_space: find_value(record, IE::SamplingTimeSpace).and_then(as_u32),
        sampling_size: find_value(record, IE::SamplingSize).and_then(as_u32),
        sampling_population: find_value(record, IE::SamplingPopulation).and_then(as_u32),
        sampling_probability: find_value(record, IE::SamplingProbability).and_then(as_f64),
        hash_ip_payload_offset: find_u64(record, IE::HashIpPayloadOffset),
        hash_ip_payload_size: find_u64(record, IE::HashIpPayloadSize),
        hash_output_range: find_u64(record, IE::HashOutputRangeMin)
            .zip(find_u64(record, IE::HashOutputRangeMax)),
        hash_selected_ranges: range_mins.into_iter().zip(range_maxes).collect(),
        hash_digest_output: find_value(record, IE::HashDigestOutput).and_then(|v| match v {
            FieldValue::Boolean(b) => Some(*b),
            _ => None,
        }),
        hash_initialiser_value: find_u64(record, IE::HashInitialiserValue),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::ipfix::parser::FieldSpecifier;

    const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const OBS_DOMAIN: u32 = 1;

    fn record(fields: &[(InformationElement, FieldValue)]) -> DataRecord {
        DataRecord(
            fields
                .iter()
                .map(|(ie, value)| {
                    (
                        FieldSpecifier::from_ie(*ie, 0),
                        Arc::from(""),
                        value.clone(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn selector_report_count_based_sampling() {
        use InformationElement as IE;

        let mut cache = PsampCache::default();
        let kind = cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::SelectorId, FieldValue::Unsigned64(5)),
                (IE::SelectorAlgorithm, FieldValue::Unsigned16(1)),
                (IE::SamplingPacketInterval, FieldValue::Unsigned32(1)),
                (IE::SamplingPacketSpace, FieldValue::Unsigned32(99)),
            ]),
        );

        assert_eq!(kind, Some(PsampReportKind::Selector));
        let selector = cache.selector(&(EXPORTER, OBS_DOMAIN, 5)).unwrap();
        assert_eq!(
            selector.algorithm_kind(),
            SelectorAlgorithm::SystematicCountBasedSampling
        );
        assert_eq!(selector.sampling_rate(), Some(100));
    }

    #[test]
    fn sequence_rate_prefers_attained_fraction() {
        use InformationElement as IE;

        let mut cache = PsampCache::default();
        let kind = cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::SelectionSequenceId, FieldValue::Unsigned64(9)),
                (
                    IE::SelectorIdTotalPktsObserved,
                    FieldValue::Unsigned64(100_000),
                ),
                (
                    IE::SelectorIdTotalPktsSelected,
                    FieldValue::Unsigned64(4_000),
                ),
                (IE::SelectorIdTotalPktsSelected, FieldValue::Unsigned64(500)),
            ]),
        );

        assert_eq!(kind, Some(PsampReportKind::SelectionSequenceStats));
        assert_eq!(
            cache.sequence_sampling_rate(&(EXPORTER, OBS_DOMAIN, 9)),
            Some(200)
        );
    }

    #[test]
    fn sequence_rate_from_configured_selector_chain() {
        use InformationElement as IE;

        let mut cache = PsampCache::default();

        // A filter followed by a 1-in-10 probabilistic sampler.
        cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::SelectorId, FieldValue::Unsigned64(1)),
                (IE::SelectorAlgorithm, FieldValue::Unsigned16(6)),
                (IE::HashSelectedRangeMin, FieldValue::Unsigned64(0)),
                (IE::HashSelectedRangeMax, FieldValue::Unsigned64(1023)),
            ]),
        );
        cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::SelectorId, FieldValue::Unsigned64(2)),
                (IE::SelectorAlgorithm, FieldValue::Unsigned16(4)),
                (IE::SamplingProbability, FieldValue::Float64(0.1)),
            ]),
        );
        let kind = cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::SelectionSequenceId, FieldValue::Unsigned64(9)),
                (IE::SelectorId, FieldValue::Unsigned64(1)),
                (IE::SelectorId, FieldValue::Unsigned64(2)),
            ]),
        );

        assert_eq!(kind, Some(PsampReportKind::SelectionSequence));
        let sequence = cache.sequence(&(EXPORTER, OBS_DOMAIN, 9)).unwrap();
        assert_eq!(sequence.selector_ids, vec![1, 2]);
        assert_eq!(
            cache.sequence_sampling_rate(&(EXPORTER, OBS_DOMAIN, 9)),
            Some(10)
        );

        let filter = cache.selector(&(EXPORTER, OBS_DOMAIN, 1)).unwrap();
        assert_eq!(filter.hash_selected_ranges, vec![(0, 1023)]);
    }

    #[test]
    fn unrelated_options_data_is_ignored() {
        use InformationElement as IE;

        let mut cache = PsampCache::default();
        let kind = cache.update_from_options_data(
            EXPORTER,
            OBS_DOMAIN,
            &record(&[
                (IE::ObservationDomainId, FieldValue::Unsigned32(1)),
                (IE::SamplingPacketInterval, FieldValue::Unsigned32(100)),
            ]),
        );

        assert_eq!(kind, None);
    }
}
