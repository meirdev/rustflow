use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{FieldSpecifier, OptionsTemplateRecord, TemplateRecord};

pub const FLOW_TEMPLATE_ID: u16 = 256;
pub const OPTIONS_TEMPLATE_ID: u16 = 257;

fn field_specifier_from_ie(ie: InformationElement, field_length: u16) -> FieldSpecifier {
    FieldSpecifier {
        enterprise_bit: false,
        information_element_identifier: ie.into(),
        field_length,
        enterprise_number: None,
    }
}

pub fn create_flow_template() -> TemplateRecord {
    use InformationElement::*;

    let fields = vec![
        field_specifier_from_ie(SourceIpv4Address, 4),
        field_specifier_from_ie(DestinationIpv4Address, 4),
        field_specifier_from_ie(ProtocolIdentifier, 1),
        field_specifier_from_ie(SourceTransportPort, 2),
        field_specifier_from_ie(DestinationTransportPort, 2),
        field_specifier_from_ie(OctetDeltaCount, 8),
        field_specifier_from_ie(PacketDeltaCount, 8),
        field_specifier_from_ie(TcpControlBits, 2),
        field_specifier_from_ie(FlowStartMilliseconds, 8),
        field_specifier_from_ie(FlowEndMilliseconds, 8),
    ];

    TemplateRecord::new(FLOW_TEMPLATE_ID, fields)
}

pub fn create_options_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    let fields = vec![
        field_specifier_from_ie(ObservationDomainId, 4),
        field_specifier_from_ie(SamplingPacketInterval, 4),
    ];

    OptionsTemplateRecord::new(OPTIONS_TEMPLATE_ID, 1, fields)
}
