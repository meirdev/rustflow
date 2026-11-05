use rustflow_bytes::Writer;

use super::*;
use crate::WriteError;
use crate::error::fit_u16;
use crate::value::{Value, encode, natural_length};

/// Writes `packet` as an IPFIX message at the end of `buf`. The lengths
/// written are those of what is written, whatever the packet holds. Sets are
/// not padded, and unknown sets, whose records were not kept, are left out.
/// On error, nothing is written.
pub fn write(packet: &Packet, buf: &mut Vec<u8>) -> Result<(), WriteError> {
    Writer::new(buf).transaction(|w| write_message(w, packet))
}

fn write_message(w: &mut Writer, packet: &Packet) -> Result<(), WriteError> {
    let Header {
        version,
        length: _,
        export_time,
        sequence_number,
        observation_domain_id,
    } = packet.header;
    let start = w.len();
    w.u16(version);
    w.u16(0);
    w.u32(export_time);
    w.u32(sequence_number);
    w.u32(observation_domain_id);
    for set in &packet.sets {
        match set {
            Set::Templates(templates) => write_set(w, TEMPLATE_SET_ID, |w| {
                templates.iter().try_for_each(|t| write_template(w, t))
            })?,
            Set::OptionsTemplates(templates) => write_set(w, OPTIONS_TEMPLATE_SET_ID, |w| {
                templates
                    .iter()
                    .try_for_each(|t| write_options_template(w, t))
            })?,
            Set::Data(data) => {
                let template = &data.template;
                write_data_set(w, template.template_id, &template.fields, &data.records)?;
            }
            Set::OptionsData(data) => {
                let template = &data.template;
                let fields = [&template.scope_fields[..], &template.option_fields].concat();
                write_data_set(w, template.template_id, &fields, &data.records)?;
            }
            Set::Unknown(_) => {}
        }
    }
    fill_length(w, start, "message length")
}

/// Sets the 16-bit length two bytes after `start` to that of everything
/// written from `start` on, as a message, set and list group each have.
fn fill_length(w: &mut Writer, start: usize, field: &'static str) -> Result<(), WriteError> {
    let length = fit_u16(w.len() - start, field)?;
    w.set_u16(start + 2, length);
    Ok(())
}

fn write_set(
    w: &mut Writer,
    set_id: u16,
    body: impl FnOnce(&mut Writer) -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    let start = w.len();
    w.u16(set_id);
    w.u16(0);
    body(w)?;
    fill_length(w, start, "set length")
}

fn write_template(w: &mut Writer, template: &Template) -> Result<(), WriteError> {
    w.u16(template.template_id);
    w.u16(fit_u16(template.fields.len(), "field count")?);
    template
        .fields
        .iter()
        .try_for_each(|field| write_field_specifier(w, field))
}

fn write_options_template(w: &mut Writer, template: &OptionsTemplate) -> Result<(), WriteError> {
    let OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    } = template;
    let field_count = fit_u16(scope_fields.len() + option_fields.len(), "field count")?;
    w.u16(*template_id);
    w.u16(field_count);
    // A withdrawal has no scope field count (RFC 7011 section 8.1).
    if field_count == 0 {
        return Ok(());
    }
    if scope_fields.is_empty() {
        return Err(WriteError::NoScopeFields {
            template_id: *template_id,
        });
    }
    w.u16(fit_u16(scope_fields.len(), "scope field count")?);
    scope_fields
        .iter()
        .chain(option_fields)
        .try_for_each(|field| write_field_specifier(w, field))
}

fn write_field_specifier(w: &mut Writer, field: &FieldSpecifier) -> Result<(), WriteError> {
    let id = field.information_element_id;
    if id & ENTERPRISE_BIT != 0 {
        return Err(WriteError::TooLarge {
            field: "information element ID",
            value: usize::from(id),
        });
    }
    match field.enterprise_number {
        Some(enterprise_number) => {
            w.u16(id | ENTERPRISE_BIT);
            w.u16(field.field_length);
            w.u32(enterprise_number);
        }
        None => {
            w.u16(id);
            w.u16(field.field_length);
        }
    }
    Ok(())
}

fn write_data_set(
    w: &mut Writer,
    template_id: u16,
    fields: &[FieldSpecifier],
    records: &[Vec<Value>],
) -> Result<(), WriteError> {
    write_set(w, template_id, |w| {
        records
            .iter()
            .try_for_each(|record| write_record(w, fields, record))
    })
}

fn write_record(
    w: &mut Writer,
    fields: &[FieldSpecifier],
    record: &[Value],
) -> Result<(), WriteError> {
    if record.len() != fields.len() {
        return Err(WriteError::Values {
            values: record.len(),
            fields: fields.len(),
        });
    }
    fields
        .iter()
        .zip(record)
        .try_for_each(|(field, value)| write_field(w, value, field.field_length))
}

/// Writes a value as a field `field_length` octets long, or with its length
/// before it for a variable-length field.
fn write_field(w: &mut Writer, value: &Value, field_length: u16) -> Result<(), WriteError> {
    match value {
        Value::BasicList(list) => write_list_field(w, field_length, |w| write_basic_list(w, list)),
        Value::SubTemplateList(list) => {
            write_list_field(w, field_length, |w| write_sub_template_list(w, list))
        }
        Value::SubTemplateMultiList(list) => {
            write_list_field(w, field_length, |w| write_sub_template_multi_list(w, list))
        }
        _ => match natural_length(value) {
            Some(length) if field_length == VARIABLE_LENGTH => {
                write_variable_length(w, length)?;
                encode(w, value, length)
            }
            _ => encode(w, value, usize::from(field_length)),
        },
    }
}

/// A variable-length value's length: one octet below 255, or 255 and two
/// more (RFC 7011 section 7).
fn write_variable_length(w: &mut Writer, length: usize) -> Result<(), WriteError> {
    match u8::try_from(length) {
        Ok(length) if length < 255 => w.u8(length),
        _ => {
            let length = fit_u16(length, "variable-length value")?;
            w.u8(255);
            w.u16(length);
        }
    }
    Ok(())
}

/// A list's length is known only once it is written. In a variable-length
/// field, it takes the three-octet form, filled in after (RFC 6313 section
/// 5.1 recommends that form for lists); in a fixed-length field, it must
/// come to the field's length.
fn write_list_field(
    w: &mut Writer,
    field_length: u16,
    write_list: impl FnOnce(&mut Writer) -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    if field_length == VARIABLE_LENGTH {
        w.u8(255);
        let start = w.len();
        w.u16(0);
        write_list(w)?;
        let length = fit_u16(w.len() - start - 2, "variable-length value")?;
        w.set_u16(start, length);
        return Ok(());
    }
    let length = usize::from(field_length);
    let start = w.len();
    write_list(w)?;
    if w.len() - start != length {
        return Err(WriteError::DoesNotFit { length });
    }
    Ok(())
}

fn write_basic_list(w: &mut Writer, list: &BasicList) -> Result<(), WriteError> {
    w.u8(list.semantic.into());
    write_field_specifier(w, &list.field)?;
    list.values
        .iter()
        .try_for_each(|value| write_field(w, value, list.field.field_length))
}

fn write_sub_template_list(w: &mut Writer, list: &SubTemplateList) -> Result<(), WriteError> {
    w.u8(list.semantic.into());
    w.u16(list_template_id(&list.records));
    write_list_records(w, &list.records)
}

fn write_sub_template_multi_list(
    w: &mut Writer,
    list: &SubTemplateMultiList,
) -> Result<(), WriteError> {
    w.u8(list.semantic.into());
    list.groups.iter().try_for_each(|records| {
        let start = w.len();
        w.u16(list_template_id(records));
        w.u16(0);
        write_list_records(w, records)?;
        fill_length(w, start, "list group length")
    })
}

fn list_template_id(records: &ListRecords) -> u16 {
    match records {
        ListRecords::Decoded { template, .. } => template.template_id(),
        ListRecords::Undecoded { template_id, .. } => *template_id,
    }
}

fn write_list_records(w: &mut Writer, records: &ListRecords) -> Result<(), WriteError> {
    match records {
        ListRecords::Decoded { template, records } => {
            let fields: Vec<_> = template.fields().copied().collect();
            records
                .iter()
                .try_for_each(|record| write_record(w, &fields, record))
        }
        ListRecords::Undecoded { data, .. } => {
            w.bytes(data);
            Ok(())
        }
    }
}
