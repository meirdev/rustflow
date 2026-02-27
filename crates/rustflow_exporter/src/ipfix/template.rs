use byteorder::{NetworkEndian, WriteBytesExt};
use std::io::Write;

use super::message::SetHeader;
use super::{InformationElement, OPTIONS_TEMPLATE_SET_ID, TEMPLATE_SET_ID};
use super::{FLOW_TEMPLATE_ID, OPTIONS_TEMPLATE_ID};

#[derive(Debug, Clone)]
pub struct FieldSpecifier {
    pub information_element_id: u16,
    pub field_length: u16,
}

impl FieldSpecifier {
    pub fn new(information_element_id: u16, field_length: u16) -> Self {
        Self {
            information_element_id,
            field_length,
        }
    }

    pub fn from_ie(ie: InformationElement, field_length: u16) -> Self {
        Self {
            information_element_id: ie.into(),
            field_length,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u16::<NetworkEndian>(self.information_element_id)?;
        writer.write_u16::<NetworkEndian>(self.field_length)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

impl TemplateRecord {
    pub fn new(template_id: u16, fields: Vec<FieldSpecifier>) -> Self {
        let field_count = fields.len() as u16;
        Self {
            template_id,
            field_count,
            fields,
        }
    }

    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Template Record Header
        buffer.write_u16::<NetworkEndian>(self.template_id)?;
        buffer.write_u16::<NetworkEndian>(self.field_count)?;

        // Field Specifiers
        for field in &self.fields {
            field.encode(&mut buffer)?;
        }

        Ok(buffer)
    }

    pub fn encode_as_set(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let template_data = self.encode()?;

        // Set Header: 4 bytes (Set ID + Length) + template data
        let set_length = 4 + template_data.len() as u16;
        let set_header = SetHeader::new(TEMPLATE_SET_ID, set_length);

        set_header.encode(&mut buffer)?;
        buffer.write_all(&template_data)?;

        Ok(buffer)
    }
}

#[derive(Debug, Clone)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

impl OptionsTemplateRecord {
    pub fn new(template_id: u16, scope_field_count: u16, fields: Vec<FieldSpecifier>) -> Self {
        let field_count = fields.len() as u16;
        Self {
            template_id,
            field_count,
            scope_field_count,
            fields,
        }
    }

    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Options Template Record Header
        buffer.write_u16::<NetworkEndian>(self.template_id)?;
        buffer.write_u16::<NetworkEndian>(self.field_count)?;
        buffer.write_u16::<NetworkEndian>(self.scope_field_count)?;

        // Field Specifiers (scope fields first, then option fields)
        for field in &self.fields {
            field.encode(&mut buffer)?;
        }

        Ok(buffer)
    }

    pub fn encode_as_set(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let template_data = self.encode()?;

        // Set Header: 4 bytes (Set ID + Length) + template data
        let set_length = 4 + template_data.len() as u16;
        let set_header = SetHeader::new(OPTIONS_TEMPLATE_SET_ID, set_length);

        set_header.encode(&mut buffer)?;
        buffer.write_all(&template_data)?;

        Ok(buffer)
    }
}

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
        FieldSpecifier::from_ie(ForwardingStatus, 4),
    ];

    TemplateRecord::new(FLOW_TEMPLATE_ID, fields)
}

pub fn create_options_template() -> OptionsTemplateRecord {
    use InformationElement::*;

    // The scope field identifies what the option applies to
    let fields = vec![
        FieldSpecifier::from_ie(ObservationDomainId, 4), // scope field
        FieldSpecifier::from_ie(SamplingPacketInterval, 4), // option field
    ];

    OptionsTemplateRecord::new(OPTIONS_TEMPLATE_ID, 1, fields)
}
