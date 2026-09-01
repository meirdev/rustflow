use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{FieldSpecifier, OptionsTemplateRecord, TemplateRecord};

pub const FLOW_TEMPLATE_ID: u16 = 256;
pub const OPTIONS_TEMPLATE_ID: u16 = 257;

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
