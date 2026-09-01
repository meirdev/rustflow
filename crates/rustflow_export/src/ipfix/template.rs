use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{FieldSpecifier, OptionsTemplateRecord, TemplateRecord};

use crate::capture::SamplingConfig;

pub const FLOW_TEMPLATE_ID: u16 = 256;
pub const OPTIONS_TEMPLATE_ID: u16 = 257;
pub const PACKET_REPORT_TEMPLATE_ID: u16 = 258;
pub const SELECTOR_TEMPLATE_ID: u16 = 259;
pub const SEQUENCE_TEMPLATE_ID: u16 = 260;
pub const STATS_TEMPLATE_ID: u16 = 261;

/// IPFIX variable-length field marker (RFC 7011 section 7).
pub const VARIABLE_LENGTH: u16 = 0xffff;

pub fn create_flow_template() -> TemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(SourceIpv4Address, 4),
        FieldSpecifier::from_ie(DestinationIpv4Address, 4),
        FieldSpecifier::from_ie(ProtocolIdentifier, 1),
        FieldSpecifier::from_ie(SourceTransportPort, 2),
        FieldSpecifier::from_ie(DestinationTransportPort, 2),
        FieldSpecifier::from_ie(OctetDeltaCount, 8),
        FieldSpecifier::from_ie(PacketDeltaCount, 8),
        FieldSpecifier::from_ie(TcpControlBits, 2),
        FieldSpecifier::from_ie(FlowStartMilliseconds, 8),
        FieldSpecifier::from_ie(FlowEndMilliseconds, 8),
    ];

    TemplateRecord::new(FLOW_TEMPLATE_ID, fields)
}

pub fn create_options_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(ObservationDomainId, 4),
        FieldSpecifier::from_ie(SamplingPacketInterval, 4),
    ];

    OptionsTemplateRecord::new(OPTIONS_TEMPLATE_ID, 1, fields)
}

/// PSAMP Packet Report (RFC 5476 section 6.4): one record per selected packet.
pub fn create_packet_report_template() -> TemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(SelectionSequenceId, 8),
        FieldSpecifier::from_ie(ObservationTimeMilliseconds, 8),
        FieldSpecifier::from_ie(DataLinkFrameSize, 2),
        FieldSpecifier::from_ie(DataLinkFrameSection, VARIABLE_LENGTH),
    ];

    TemplateRecord::new(PACKET_REPORT_TEMPLATE_ID, fields)
}

/// PSAMP Selector Report Interpretation (RFC 5476 section 6.5.2), scoped on
/// `selectorId`: the selector's algorithm and its parameters. The parameter
/// fields depend on the configured sampling algorithm.
pub fn create_selector_template(sampling: &SamplingConfig) -> OptionsTemplateRecord {
    use InformationElement::*;

    let mut fields = vec![
        FieldSpecifier::from_ie(SelectorId, 8),
        FieldSpecifier::from_ie(SelectorAlgorithm, 2),
    ];
    match sampling {
        SamplingConfig::CountBased { .. } => {
            fields.push(FieldSpecifier::from_ie(SamplingPacketInterval, 4));
            fields.push(FieldSpecifier::from_ie(SamplingPacketSpace, 4));
        }
        SamplingConfig::TimeBased { .. } => {
            fields.push(FieldSpecifier::from_ie(SamplingTimeInterval, 4));
            fields.push(FieldSpecifier::from_ie(SamplingTimeSpace, 4));
        }
        SamplingConfig::NOutOfN { .. } => {
            fields.push(FieldSpecifier::from_ie(SamplingSize, 4));
            fields.push(FieldSpecifier::from_ie(SamplingPopulation, 4));
        }
        SamplingConfig::Probabilistic { .. } => {
            fields.push(FieldSpecifier::from_ie(SamplingProbability, 8));
        }
    }

    OptionsTemplateRecord::new(SELECTOR_TEMPLATE_ID, 1, fields)
}

/// PSAMP Selection Sequence Report Interpretation (RFC 5476 section 6.5.1),
/// scoped on `selectionSequenceId`: the observation point and the selectors
/// applied in order.
pub fn create_sequence_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(SelectionSequenceId, 8),
        FieldSpecifier::from_ie(IngressInterface, 4),
        FieldSpecifier::from_ie(SelectorId, 8),
    ];

    OptionsTemplateRecord::new(SEQUENCE_TEMPLATE_ID, 1, fields)
}

/// PSAMP Selection Sequence Statistics Report Interpretation (RFC 5476
/// section 6.5.3), scoped on `selectionSequenceId`: packets observed and
/// selected, exported periodically.
pub fn create_stats_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(SelectionSequenceId, 8),
        FieldSpecifier::from_ie(SelectorIdTotalPktsObserved, 8),
        FieldSpecifier::from_ie(SelectorIdTotalPktsSelected, 8),
    ];

    OptionsTemplateRecord::new(STATS_TEMPLATE_ID, 1, fields)
}
