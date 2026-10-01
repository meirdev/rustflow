use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{
    FieldSpecifier, IPFIX_VARIABLE_LENGTH, OptionsTemplateRecord, TemplateRecord,
};

use crate::capture::Link;
use crate::meter::Mode;
use crate::sampler::Sampling;

pub const FLOW_IPV4_TEMPLATE_ID: u16 = 256;
pub const FLOW_IPV6_TEMPLATE_ID: u16 = 257;
pub const OPTIONS_TEMPLATE_ID: u16 = 258;
pub const PACKET_FRAME_TEMPLATE_ID: u16 = 259;
pub const PACKET_IP_TEMPLATE_ID: u16 = 260;

pub fn create_templates(mode: Mode) -> Vec<TemplateRecord> {
    match mode {
        Mode::Flow => create_flow_templates().to_vec(),
        Mode::Packet => [Link::Ethernet, Link::Ip]
            .map(create_packet_template)
            .to_vec(),
    }
}

pub fn packet_template_id(link: Link) -> u16 {
    match link {
        Link::Ethernet => PACKET_FRAME_TEMPLATE_ID,
        Link::Ip => PACKET_IP_TEMPLATE_ID,
    }
}

pub fn packet_fields(link: Link) -> [FieldSpecifier; 2] {
    use InformationElement::*;

    let section = match link {
        Link::Ethernet => DataLinkFrameSection,
        Link::Ip => IpHeaderPacketSection,
    };
    [
        FieldSpecifier::from_ie(DataLinkFrameSize, 2),
        FieldSpecifier::from_ie(section, IPFIX_VARIABLE_LENGTH),
    ]
}

fn create_packet_template(link: Link) -> TemplateRecord {
    TemplateRecord::new(packet_template_id(link), packet_fields(link).to_vec())
}

fn create_flow_templates() -> [TemplateRecord; 2] {
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

pub fn create_options_template(sampling: Sampling) -> OptionsTemplateRecord {
    use InformationElement::*;

    let mut fields = vec![FieldSpecifier::from_ie(ObservationDomainId, 4)];
    match sampling {
        Sampling::Count { .. } => fields.extend([
            FieldSpecifier::from_ie(SamplingInterval, 4),
            FieldSpecifier::from_ie(SelectorAlgorithm, 2),
            FieldSpecifier::from_ie(SamplingPacketInterval, 4),
            FieldSpecifier::from_ie(SamplingPacketSpace, 4),
        ]),
    }

    OptionsTemplateRecord::new(OPTIONS_TEMPLATE_ID, 1, fields)
}
