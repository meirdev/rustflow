use std::fmt;

use bytes::BufMut;

use super::*;
use crate::template::FieldSpecifier;
use crate::value::{self, Value, encode_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    BufferTooSmall {
        needed: usize,
        remaining: usize,
    },
    FlowSetTooLong {
        flow_set_id: u16,
        length: usize,
    },
    TooManyFields {
        template_id: u16,
    },
    EnterpriseField {
        template_id: u16,
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
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, remaining } => write!(
                f,
                "the packet needs {needed} octets, the buffer has room for {remaining}"
            ),
            Self::FlowSetTooLong {
                flow_set_id,
                length,
            } => write!(
                f,
                "FlowSet {flow_set_id} is {length} octets, more than its length field holds"
            ),
            Self::TooManyFields { template_id } => {
                write!(f, "template {template_id} has too many fields")
            }
            Self::EnterpriseField { template_id } => write!(
                f,
                "template {template_id} has a field with an enterprise number"
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
    let Packet { header, flow_sets } = packet;
    let Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        sequence_number,
        source_id,
    } = *header;
    out.put_u16(version);
    out.put_u16(count);
    out.put_u32(sys_uptime);
    out.put_u32(unix_secs);
    out.put_u32(sequence_number);
    out.put_u32(source_id);
    flow_sets
        .iter()
        .try_for_each(|flow_set| encode_flow_set(out, flow_set))
}

fn encode_flow_set(out: &mut Vec<u8>, flow_set: &FlowSet) -> Result {
    let start = out.len();
    let flow_set_id = match flow_set {
        FlowSet::Templates(_) => TEMPLATE_FLOW_SET_ID,
        FlowSet::OptionsTemplates(_) => OPTIONS_TEMPLATE_FLOW_SET_ID,
        FlowSet::Data(data) => data.template.template_id,
        FlowSet::OptionsData(data) => data.template.template_id,
        FlowSet::Undecoded {
            set_id: flow_set_id,
            ..
        }
        | FlowSet::Unknown(flow_set_id) => *flow_set_id,
    };
    out.put_u16(flow_set_id);
    out.put_u16(0);

    let min_record = match flow_set {
        FlowSet::Templates(templates) => {
            for template in templates {
                encode_template(out, template)?;
            }
            TEMPLATE_RECORD_HEADER_LENGTH
        }
        FlowSet::OptionsTemplates(templates) => {
            for template in templates {
                encode_options_template(out, template)?;
            }
            OPTIONS_TEMPLATE_RECORD_HEADER_LENGTH
        }
        FlowSet::Data(data) => {
            let template = &data.template;
            let lengths = || template.fields.iter().map(|field| field.field_length);
            for record in &data.records {
                encode_record(
                    out,
                    template.template_id,
                    lengths(),
                    template.fields.len(),
                    record,
                )?;
            }
            lengths().map(usize::from).sum()
        }
        FlowSet::OptionsData(data) => {
            let template = &data.template;
            for record in &data.records {
                encode_record(
                    out,
                    template.template_id,
                    options_field_lengths(template),
                    template.scope_fields.len() + template.option_fields.len(),
                    record,
                )?;
            }
            options_field_lengths(template).map(usize::from).sum()
        }
        // As sent: any padding is already in the body.
        FlowSet::Undecoded { body, .. } => {
            out.put_slice(body);
            0
        }
        FlowSet::Unknown(_) => 0,
    };

    let body = out.len() - start - usize::from(FLOW_SET_HEADER_LENGTH);
    let padding = (4 - body % 4) % 4;
    if padding < min_record {
        out.put_bytes(0, padding);
    }
    let length = out.len() - start;
    let field = u16::try_from(length).map_err(|_| EncodeError::FlowSetTooLong {
        flow_set_id,
        length,
    })?;
    out[start + 2..start + 4].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

fn encode_template(out: &mut Vec<u8>, template: &Template) -> Result {
    let Template {
        template_id,
        fields,
    } = template;
    let field_count = u16::try_from(fields.len()).map_err(|_| EncodeError::TooManyFields {
        template_id: *template_id,
    })?;
    out.put_u16(*template_id);
    out.put_u16(field_count);
    fields
        .iter()
        .try_for_each(|field| encode_field_specifier(out, *template_id, field))
}

fn encode_options_template(out: &mut Vec<u8>, template: &OptionsTemplate<ScopeField>) -> Result {
    let OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    } = template;
    // Lengths in octets, four per field.
    let octets = |count: usize| {
        count
            .checked_mul(4)
            .and_then(|octets| u16::try_from(octets).ok())
            .ok_or(EncodeError::TooManyFields {
                template_id: *template_id,
            })
    };
    out.put_u16(*template_id);
    out.put_u16(octets(scope_fields.len())?);
    out.put_u16(octets(option_fields.len())?);
    for scope in scope_fields {
        let ScopeField { field_type, length } = *scope;
        out.put_u16(field_type.into());
        out.put_u16(length);
    }
    option_fields
        .iter()
        .try_for_each(|field| encode_field_specifier(out, *template_id, field))
}

fn encode_field_specifier(out: &mut Vec<u8>, template_id: u16, field: &FieldSpecifier) -> Result {
    let FieldSpecifier {
        information_element_id,
        field_length,
        enterprise_number,
    } = *field;
    if enterprise_number.is_some() {
        return Err(EncodeError::EnterpriseField { template_id });
    }
    out.put_u16(information_element_id);
    out.put_u16(field_length);
    Ok(())
}

fn encode_record(
    out: &mut Vec<u8>,
    template_id: u16,
    lengths: impl Iterator<Item = u16>,
    fields: usize,
    values: &[Value],
) -> Result {
    if values.len() != fields {
        return Err(EncodeError::RecordLength {
            template_id,
            fields,
            values: values.len(),
        });
    }
    for (field, (length, value)) in lengths.zip(values).enumerate() {
        encode_value(out, value, length).map_err(|error| EncodeError::Value {
            template_id,
            field,
            error,
        })?;
    }
    Ok(())
}

fn options_field_lengths(template: &OptionsTemplate<ScopeField>) -> impl Iterator<Item = u16> + '_ {
    let scope = template.scope_fields.iter().map(|scope| scope.length);
    let options = template
        .option_fields
        .iter()
        .map(|field| field.field_length);
    scope.chain(options)
}
