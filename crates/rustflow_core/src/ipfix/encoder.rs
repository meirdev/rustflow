use std::fmt;

use bytes::BufMut;

use super::*;
use crate::template::TemplateRef;
use crate::value::{
    self, BasicList, ListRecords, SubTemplateList, SubTemplateMultiList, Value, encode_value,
    natural_length,
};

const LONG_LENGTH: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    BufferTooSmall {
        needed: usize,
        remaining: usize,
    },
    MessageTooLong {
        length: usize,
    },
    SetTooLong {
        set_id: u16,
        length: usize,
    },
    InvalidTemplateId(u16),
    TooManyFields {
        template_id: u16,
    },
    NoScopeFields {
        template_id: u16,
    },
    InvalidElementId {
        template_id: u16,
        element_id: u16,
    },
    RecordLength {
        template_id: u16,
        fields: usize,
        values: usize,
    },
    Value {
        template_id: u16,
        field: usize,
        error: value::EncodeError,
    },
    FieldTooLong {
        template_id: u16,
        field: usize,
        length: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, remaining } => write!(
                f,
                "the message needs {needed} octets, the buffer has room for {remaining}"
            ),
            Self::MessageTooLong { length } => {
                write!(
                    f,
                    "the message is {length} octets, more than its length field holds"
                )
            }
            Self::SetTooLong { set_id, length } => {
                write!(
                    f,
                    "set {set_id} is {length} octets, more than its length field holds"
                )
            }
            Self::InvalidTemplateId(template_id) => write!(f, "invalid template ID {template_id}"),
            Self::TooManyFields { template_id } => {
                write!(f, "template {template_id} has too many fields")
            }
            Self::NoScopeFields { template_id } => {
                write!(f, "options template {template_id} has no scope field")
            }
            Self::InvalidElementId {
                template_id,
                element_id,
            } => write!(
                f,
                "template {template_id}: element ID {element_id} does not fit in 15 bits"
            ),
            Self::RecordLength {
                template_id,
                fields,
                values,
            } => write!(
                f,
                "a record of template {template_id} has {values} values for {fields} fields"
            ),
            Self::Value {
                template_id, field, ..
            } => write!(
                f,
                "field {field} of template {template_id} cannot be encoded"
            ),
            Self::FieldTooLong {
                template_id,
                field,
                length,
            } => write!(
                f,
                "field {field} of template {template_id} is {length} octets, more than its length holds"
            ),
        }
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Value { error, .. } => Some(error),
            _ => None,
        }
    }
}

type Result<T = ()> = std::result::Result<T, EncodeError>;

#[derive(Clone, Copy)]
struct Field {
    template_id: u16,
    index: usize,
}

impl Field {
    fn value_error(self, error: value::EncodeError) -> EncodeError {
        EncodeError::Value {
            template_id: self.template_id,
            field: self.index,
            error,
        }
    }

    fn too_long(self, length: usize) -> EncodeError {
        EncodeError::FieldTooLong {
            template_id: self.template_id,
            field: self.index,
            length,
        }
    }
}

pub fn encode_packet(out: &mut impl BufMut, packet: &Packet) -> Result<usize> {
    let mut buffer = Vec::new();
    encode_message(&mut buffer, packet)?;
    let needed = buffer.len();
    let remaining = out.remaining_mut();
    if remaining < needed {
        return Err(EncodeError::BufferTooSmall { needed, remaining });
    }
    out.put_slice(&buffer);
    Ok(needed)
}

fn encode_message(out: &mut Vec<u8>, packet: &Packet) -> Result {
    let Packet { header, sets } = packet;
    let Header {
        version,
        length: _,
        export_time,
        sequence_number,
        observation_domain_id,
    } = *header;
    out.put_u16(version);
    out.put_u16(0);
    out.put_u32(export_time);
    out.put_u32(sequence_number);
    out.put_u32(observation_domain_id);
    for set in sets {
        encode_set(out, set)?;
    }

    let length = out.len();
    let field = u16::try_from(length).map_err(|_| EncodeError::MessageTooLong { length })?;
    out[2..4].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

fn encode_set(out: &mut Vec<u8>, set: &Set) -> Result {
    let start = out.len();
    let (set_id, template) = match set {
        Set::Templates(_) => (TEMPLATE_SET_ID, None),
        Set::OptionsTemplates(_) => (OPTIONS_TEMPLATE_SET_ID, None),
        Set::Data(data) => {
            let template = TemplateRef::Data(Arc::clone(&data.template));
            (template.template_id(), Some(template))
        }
        Set::OptionsData(data) => {
            let template = TemplateRef::Options(Arc::clone(&data.template));
            (template.template_id(), Some(template))
        }
        Set::Undecoded { set_id, .. } | Set::Unknown(set_id) => (*set_id, None),
    };
    if template.is_some() && set_id < MIN_TEMPLATE_ID {
        return Err(EncodeError::InvalidTemplateId(set_id));
    }
    out.put_u16(set_id);
    out.put_u16(0);

    let min_record = match set {
        Set::Templates(templates) => {
            for template in templates {
                encode_template(out, template)?;
            }
            MIN_TEMPLATE_RECORD_LENGTH
        }
        Set::OptionsTemplates(templates) => {
            for template in templates {
                encode_options_template(out, template)?;
            }
            MIN_TEMPLATE_RECORD_LENGTH
        }
        Set::Data(DataSet { records, .. }) | Set::OptionsData(DataSet { records, .. }) => {
            let template = template.as_ref().expect("a data set has a template");
            for record in records {
                encode_record(out, template, record)?;
            }
            min_record_length(template)
        }
        // As sent: any padding is already in the body.
        Set::Undecoded { body, .. } => {
            out.put_slice(body);
            0
        }
        Set::Unknown(_) => 0,
    };

    let body = out.len() - start - usize::from(SET_HEADER_LENGTH);
    let padding = (4 - body % 4) % 4;
    if padding < min_record {
        out.put_bytes(0, padding);
    }
    let length = out.len() - start;
    let field = u16::try_from(length).map_err(|_| EncodeError::SetTooLong { set_id, length })?;
    out[start + 2..start + 4].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

fn min_record_length(template: &TemplateRef) -> usize {
    template
        .fields()
        .map(|field| match field.field_length {
            VARIABLE_LENGTH => 1,
            length => usize::from(length),
        })
        .sum()
}

fn encode_template(out: &mut Vec<u8>, template: &Template) -> Result {
    let Template {
        template_id,
        fields,
    } = template;
    let field_count = u16::try_from(fields.len()).map_err(|_| EncodeError::TooManyFields {
        template_id: *template_id,
    })?;
    if !is_valid_template_header(*template_id, field_count, TEMPLATE_SET_ID) {
        return Err(EncodeError::InvalidTemplateId(*template_id));
    }
    out.put_u16(*template_id);
    out.put_u16(field_count);
    fields
        .iter()
        .try_for_each(|field| encode_field_specifier(out, *template_id, field))
}

fn encode_options_template(out: &mut Vec<u8>, template: &OptionsTemplate) -> Result {
    let OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    } = template;
    let too_many = || EncodeError::TooManyFields {
        template_id: *template_id,
    };
    let field_count =
        u16::try_from(scope_fields.len() + option_fields.len()).map_err(|_| too_many())?;
    if !is_valid_template_header(*template_id, field_count, OPTIONS_TEMPLATE_SET_ID) {
        return Err(EncodeError::InvalidTemplateId(*template_id));
    }
    if field_count != 0 && scope_fields.is_empty() {
        return Err(EncodeError::NoScopeFields {
            template_id: *template_id,
        });
    }
    out.put_u16(*template_id);
    out.put_u16(field_count);
    if field_count != 0 {
        out.put_u16(scope_fields.len() as u16);
    }
    scope_fields
        .iter()
        .chain(option_fields)
        .try_for_each(|field| encode_field_specifier(out, *template_id, field))
}

fn encode_field_specifier(out: &mut Vec<u8>, template_id: u16, field: &FieldSpecifier) -> Result {
    let FieldSpecifier {
        information_element_id,
        field_length,
        enterprise_number,
    } = *field;
    if information_element_id & ENTERPRISE_BIT != 0 {
        return Err(EncodeError::InvalidElementId {
            template_id,
            element_id: information_element_id,
        });
    }
    match enterprise_number {
        Some(enterprise_number) => {
            out.put_u16(information_element_id | ENTERPRISE_BIT);
            out.put_u16(field_length);
            out.put_u32(enterprise_number);
        }
        None => {
            out.put_u16(information_element_id);
            out.put_u16(field_length);
        }
    }
    Ok(())
}

fn encode_record(out: &mut Vec<u8>, template: &TemplateRef, values: &[Value]) -> Result {
    let template_id = template.template_id();
    let fields = template.fields().count();
    if values.len() != fields {
        return Err(EncodeError::RecordLength {
            template_id,
            fields,
            values: values.len(),
        });
    }
    for (index, (field, value)) in template.fields().zip(values).enumerate() {
        encode_field(out, Field { template_id, index }, value, field.field_length)?;
    }
    Ok(())
}

fn encode_field(out: &mut Vec<u8>, at: Field, value: &Value, length: u16) -> Result {
    if length != VARIABLE_LENGTH {
        let start = out.len();
        encode_content(out, at, value, Some(length))?;
        // Only a list can come out another length than asked.
        if out.len() - start != usize::from(length) {
            return Err(at.value_error(value::EncodeError::InvalidLength { length }));
        }
        return Ok(());
    }

    // A one-octet prefix, widened to 255 and a two-octet length once the
    // content turns out to be longer.
    let prefix_at = out.len();
    out.put_u8(0);
    encode_content(out, at, value, None)?;
    let content = out.len() - prefix_at - 1;
    if content < usize::from(LONG_LENGTH) {
        out[prefix_at] = content as u8;
    } else {
        let long = u16::try_from(content).map_err(|_| at.too_long(content))?;
        out[prefix_at] = LONG_LENGTH;
        out.splice(prefix_at + 1..prefix_at + 1, long.to_be_bytes());
    }
    Ok(())
}

fn encode_content(out: &mut Vec<u8>, at: Field, value: &Value, length: Option<u16>) -> Result {
    match value {
        Value::BasicList(list) => encode_basic_list(out, at, list),
        Value::SubTemplateList(list) => {
            let SubTemplateList { semantic, records } = list.as_ref();
            out.put_u8((*semantic).into());
            encode_list_records(out, records)
        }
        Value::SubTemplateMultiList(list) => {
            let SubTemplateMultiList { semantic, groups } = list.as_ref();
            out.put_u8((*semantic).into());
            groups
                .iter()
                .try_for_each(|group| encode_list_group(out, at, group))
        }
        _ => {
            let length = match length {
                Some(length) => length,
                None => {
                    let natural = natural_length(value)
                        .ok_or(at.value_error(value::EncodeError::Unsupported))?;
                    u16::try_from(natural).map_err(|_| at.too_long(natural))?
                }
            };
            encode_value(out, value, length)
                .map(drop)
                .map_err(|error| at.value_error(error))
        }
    }
}

fn encode_basic_list(out: &mut Vec<u8>, at: Field, list: &BasicList) -> Result {
    let BasicList {
        semantic,
        field,
        values,
    } = list;
    out.put_u8((*semantic).into());
    encode_field_specifier(out, at.template_id, field)?;
    values
        .iter()
        .try_for_each(|value| encode_field(out, at, value, field.field_length))
}

fn encode_list_records(out: &mut Vec<u8>, records: &ListRecords) -> Result {
    out.put_u16(list_template_id(records));
    encode_list_records_body(out, records)
}

fn encode_list_group(out: &mut Vec<u8>, at: Field, group: &ListRecords) -> Result {
    let start = out.len();
    out.put_u16(list_template_id(group));
    out.put_u16(0);
    encode_list_records_body(out, group)?;
    let length = out.len() - start;
    let field = u16::try_from(length).map_err(|_| at.too_long(length))?;
    out[start + 2..start + 4].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

fn list_template_id(records: &ListRecords) -> u16 {
    match records {
        ListRecords::Decoded { template, .. } => template.template_id(),
        ListRecords::Undecoded { template_id, .. } => *template_id,
    }
}

fn encode_list_records_body(out: &mut Vec<u8>, records: &ListRecords) -> Result {
    match records {
        ListRecords::Decoded { template, records } => records
            .iter()
            .try_for_each(|record| encode_record(out, template, record)),
        ListRecords::Undecoded { data, .. } => {
            out.put_slice(data);
            Ok(())
        }
    }
}
