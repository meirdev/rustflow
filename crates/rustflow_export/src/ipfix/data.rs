use std::net::Ipv4Addr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{DataRecord, FieldSpecifier, FieldValue};

use crate::capture::SamplingConfig;
use crate::ipfix::template::VARIABLE_LENGTH;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ipv4: Ipv4Addr,
    pub destination_ipv4: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
}

impl FlowData {
    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Ipv4Address(self.source_ipv4),
            FieldValue::Ipv4Address(self.destination_ipv4),
            FieldValue::Unsigned8(self.protocol),
            FieldValue::Unsigned16(self.source_port),
            FieldValue::Unsigned16(self.destination_port),
            FieldValue::Unsigned64(self.octet_count),
            FieldValue::Unsigned64(self.packet_count),
            FieldValue::Unsigned16(self.tcp_flags),
            FieldValue::DateTimeMilliseconds(self.flow_start),
            FieldValue::DateTimeMilliseconds(self.flow_end),
        ])
    }
}

#[derive(Debug)]
pub struct OptionsData {
    pub observation_domain_id: u32,
    pub sampling_packet_interval: u32,
}

impl OptionsData {
    pub fn new(observation_domain_id: u32, sampling_packet_interval: u32) -> Self {
        Self {
            observation_domain_id,
            sampling_packet_interval,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Unsigned32(self.observation_domain_id),
            FieldValue::Unsigned32(self.sampling_packet_interval),
        ])
    }
}

/// A PSAMP Packet Report (RFC 5476 section 6.4).
#[derive(Debug, Clone)]
pub struct PacketReport {
    pub selection_sequence_id: u64,
    pub observation_time: DateTime<Utc>,
    /// Original frame length on the wire (dataLinkFrameSize).
    pub frame_length: u16,
    /// Leading bytes of the frame (dataLinkFrameSection).
    pub section: Vec<u8>,
}

impl PacketReport {
    /// Encoded size of this record on the wire, including the
    /// variable-length prefix.
    pub fn encoded_len(&self) -> usize {
        let prefix = if self.section.len() < 255 { 1 } else { 3 };
        8 + 8 + 2 + prefix + self.section.len()
    }

    pub fn to_data_record(&self) -> DataRecord {
        let name: Arc<str> = Arc::from("");
        // The section needs an explicit variable-length field specifier so
        // the encoder writes the RFC 7011 section 7 length prefix.
        DataRecord(vec![
            (
                FieldSpecifier::from_ie(InformationElement::SelectionSequenceId, 8),
                name.clone(),
                FieldValue::Unsigned64(self.selection_sequence_id),
            ),
            (
                FieldSpecifier::from_ie(InformationElement::ObservationTimeMilliseconds, 8),
                name.clone(),
                FieldValue::DateTimeMilliseconds(self.observation_time),
            ),
            (
                FieldSpecifier::from_ie(InformationElement::DataLinkFrameSize, 2),
                name.clone(),
                FieldValue::Unsigned16(self.frame_length),
            ),
            (
                FieldSpecifier::from_ie(InformationElement::DataLinkFrameSection, VARIABLE_LENGTH),
                name,
                FieldValue::OctetArray(self.section.clone()),
            ),
        ])
    }
}

/// A PSAMP Selector Report Interpretation (RFC 5476 section 6.5.2). Must be
/// encoded against the template from `create_selector_template` for the same
/// [`SamplingConfig`] variant.
#[derive(Debug, Clone)]
pub struct SelectorReport {
    pub selector_id: u64,
    pub sampling: SamplingConfig,
}

impl SelectorReport {
    /// The IANA PSAMP selectorAlgorithm identifier for this configuration.
    fn algorithm_id(&self) -> u16 {
        match self.sampling {
            SamplingConfig::CountBased { .. } => 1,
            SamplingConfig::TimeBased { .. } => 2,
            SamplingConfig::NOutOfN { .. } => 3,
            SamplingConfig::Probabilistic { .. } => 4,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        let mut values = vec![
            FieldValue::Unsigned64(self.selector_id),
            FieldValue::Unsigned16(self.algorithm_id()),
        ];
        match self.sampling {
            SamplingConfig::CountBased { interval } => {
                // 1-in-N: interval counts selected packets per cycle.
                values.push(FieldValue::Unsigned32(1));
                values.push(FieldValue::Unsigned32(interval.max(1) - 1));
            }
            SamplingConfig::TimeBased {
                interval_us,
                space_us,
            } => {
                values.push(FieldValue::Unsigned32(interval_us));
                values.push(FieldValue::Unsigned32(space_us));
            }
            SamplingConfig::NOutOfN { size, population } => {
                values.push(FieldValue::Unsigned32(size));
                values.push(FieldValue::Unsigned32(population));
            }
            SamplingConfig::Probabilistic { probability } => {
                values.push(FieldValue::Float64(probability));
            }
        }
        DataRecord::new(values)
    }
}

/// A PSAMP Selection Sequence Report Interpretation (RFC 5476 section 6.5.1).
#[derive(Debug, Clone)]
pub struct SequenceReport {
    pub selection_sequence_id: u64,
    pub ingress_interface: u32,
    pub selector_id: u64,
}

impl SequenceReport {
    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Unsigned64(self.selection_sequence_id),
            FieldValue::Unsigned32(self.ingress_interface),
            FieldValue::Unsigned64(self.selector_id),
        ])
    }
}

/// A PSAMP Selection Sequence Statistics Report Interpretation (RFC 5476
/// section 6.5.3).
#[derive(Debug, Clone)]
pub struct SequenceStats {
    pub selection_sequence_id: u64,
    pub packets_observed: u64,
    pub packets_selected: u64,
}

impl SequenceStats {
    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Unsigned64(self.selection_sequence_id),
            FieldValue::Unsigned64(self.packets_observed),
            FieldValue::Unsigned64(self.packets_selected),
        ])
    }
}
