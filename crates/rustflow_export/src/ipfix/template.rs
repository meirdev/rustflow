use std::sync::{Arc, LazyLock};

use rustflow_core::information_element::ElementId;
use rustflow_core::ipfix::{FieldSpecifier, OptionsTemplate, Template, VARIABLE_LENGTH};

use crate::capture::Link;
use crate::meter::Mode;
use crate::sampler::Sampling;

pub const FLOW_IPV4_TEMPLATE_ID: u16 = 256;
pub const FLOW_IPV6_TEMPLATE_ID: u16 = 257;
pub const OPTIONS_TEMPLATE_ID: u16 = 258;
pub const PACKET_FRAME_TEMPLATE_ID: u16 = 259;
pub const PACKET_IP_TEMPLATE_ID: u16 = 260;

fn field(element: ElementId, field_length: u16) -> FieldSpecifier {
    FieldSpecifier {
        information_element_id: element.id(),
        field_length,
        enterprise_number: element.enterprise(),
    }
}

/// Every data template, built once: the flow templates, then the packet
/// ones.
static TEMPLATES: LazyLock<[Arc<Template>; 4]> = LazyLock::new(|| {
    let [ipv4, ipv6] = create_flow_templates();
    [
        ipv4,
        ipv6,
        create_packet_template(Link::Ethernet),
        create_packet_template(Link::Ip),
    ]
});

pub fn create_templates(mode: Mode) -> Vec<Arc<Template>> {
    let [ipv4, ipv6, frame, ip] = &*TEMPLATES;
    match mode {
        Mode::Flow => vec![Arc::clone(ipv4), Arc::clone(ipv6)],
        Mode::Packet => vec![Arc::clone(frame), Arc::clone(ip)],
    }
}

/// The data template of `template_id`, whichever mode it belongs to.
pub fn data_template(template_id: u16) -> Option<Arc<Template>> {
    TEMPLATES
        .iter()
        .find(|template| template.template_id == template_id)
        .cloned()
}

pub fn packet_template_id(link: Link) -> u16 {
    match link {
        Link::Ethernet => PACKET_FRAME_TEMPLATE_ID,
        Link::Ip => PACKET_IP_TEMPLATE_ID,
    }
}

fn create_packet_template(link: Link) -> Arc<Template> {
    let section = match link {
        Link::Ethernet => ElementId::DATA_LINK_FRAME_SECTION,
        Link::Ip => ElementId::IP_HEADER_PACKET_SECTION,
    };
    Arc::new(Template {
        template_id: packet_template_id(link),
        fields: vec![
            field(ElementId::DATA_LINK_FRAME_SIZE, 2),
            field(section, VARIABLE_LENGTH),
        ],
    })
}

fn create_flow_templates() -> [Arc<Template>; 2] {
    [
        flow_template(
            FLOW_IPV4_TEMPLATE_ID,
            [
                field(ElementId::SOURCE_IPV4_ADDRESS, 4),
                field(ElementId::DESTINATION_IPV4_ADDRESS, 4),
            ],
        ),
        flow_template(
            FLOW_IPV6_TEMPLATE_ID,
            [
                field(ElementId::SOURCE_IPV6_ADDRESS, 16),
                field(ElementId::DESTINATION_IPV6_ADDRESS, 16),
            ],
        ),
    ]
}

fn flow_template(template_id: u16, addresses: [FieldSpecifier; 2]) -> Arc<Template> {
    let mut fields = addresses.to_vec();
    fields.extend([
        field(ElementId::IP_VERSION, 1),
        field(ElementId::PROTOCOL_IDENTIFIER, 1),
        field(ElementId::SOURCE_TRANSPORT_PORT, 2),
        field(ElementId::DESTINATION_TRANSPORT_PORT, 2),
        field(ElementId::OCTET_DELTA_COUNT, 8),
        field(ElementId::PACKET_DELTA_COUNT, 8),
        field(ElementId::TCP_CONTROL_BITS, 2),
        field(ElementId::FLOW_START_MILLISECONDS, 8),
        field(ElementId::FLOW_END_MILLISECONDS, 8),
        field(ElementId::FLOW_END_REASON, 1),
    ]);

    Arc::new(Template {
        template_id,
        fields,
    })
}

pub fn create_options_template(sampling: Sampling) -> Arc<OptionsTemplate> {
    let option_fields = match sampling {
        Sampling::Count { .. } => vec![
            field(ElementId::SAMPLING_INTERVAL, 4),
            field(ElementId::SELECTOR_ALGORITHM, 2),
            field(ElementId::SAMPLING_PACKET_INTERVAL, 4),
            field(ElementId::SAMPLING_PACKET_SPACE, 4),
        ],
    };

    Arc::new(OptionsTemplate {
        template_id: OPTIONS_TEMPLATE_ID,
        scope_fields: vec![field(ElementId::OBSERVATION_DOMAIN_ID, 4)],
        option_fields,
    })
}
