use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{FieldSpecifier, OptionsTemplateRecord, TemplateRecord};

pub const FLOW_IPV4_TEMPLATE_ID: u16 = 256;
pub const FLOW_IPV6_TEMPLATE_ID: u16 = 257;
pub const OPTIONS_TEMPLATE_ID: u16 = 258;

pub fn create_flow_templates() -> [TemplateRecord; 2] {
    use InformationElement::*;

    [
        flow_template(
            FLOW_IPV4_TEMPLATE_ID,
            [
                FieldSpecifier::from_ie(SourceIpv4Address, 4),
                FieldSpecifier::from_ie(DestinationIpv4Address, 4),
            ],
        ),
        flow_template(
            FLOW_IPV6_TEMPLATE_ID,
            [
                FieldSpecifier::from_ie(SourceIpv6Address, 16),
                FieldSpecifier::from_ie(DestinationIpv6Address, 16),
            ],
        ),
    ]
}

fn flow_template(template_id: u16, addresses: [FieldSpecifier; 2]) -> TemplateRecord {
    use InformationElement::*;

    let mut fields = addresses.to_vec();
    fields.extend([
        FieldSpecifier::from_ie(IpVersion, 1),
        FieldSpecifier::from_ie(ProtocolIdentifier, 1),
        FieldSpecifier::from_ie(SourceTransportPort, 2),
        FieldSpecifier::from_ie(DestinationTransportPort, 2),
        FieldSpecifier::from_ie(OctetDeltaCount, 8),
        FieldSpecifier::from_ie(PacketDeltaCount, 8),
        FieldSpecifier::from_ie(TcpControlBits, 2),
        FieldSpecifier::from_ie(FlowStartMilliseconds, 8),
        FieldSpecifier::from_ie(FlowEndMilliseconds, 8),
        FieldSpecifier::from_ie(FlowEndReason, 1),
    ]);

    TemplateRecord::new(template_id, fields)
}

pub fn create_options_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    let fields = vec![
        FieldSpecifier::from_ie(ObservationDomainId, 4),
        FieldSpecifier::from_ie(SamplingPacketInterval, 4),
    ];

    OptionsTemplateRecord::new(OPTIONS_TEMPLATE_ID, 1, fields)
}
