use rustflow_bytes::Writer;

use super::*;
use crate::WriteError;
use crate::error::fit_u16;
use crate::value::{Value, encode};

/// Field Type and Field Length.
const FIELD_SIZE: usize = 4;
/// The shortest template record: Template ID and Field Count.
const MIN_TEMPLATE_SIZE: usize = 4;
/// The shortest options template record: Template ID, Option Scope Length
/// and Option Length.
const MIN_OPTIONS_TEMPLATE_SIZE: usize = 6;

/// Writes `packet` as a NetFlow v9 datagram at the end of `buf`. The count
/// and lengths written are those of what is written, whatever the packet
/// holds. Unknown FlowSets, whose records were not kept, are left out. On
/// error, nothing is written.
pub fn write(packet: &Packet, buf: &mut Vec<u8>) -> Result<(), WriteError> {
    Writer::new(buf).transaction(|w| write_packet(w, packet))
}

fn write_packet(w: &mut Writer, packet: &Packet) -> Result<(), WriteError> {
    let Header {
        version,
        count: _,
        sys_uptime,
        unix_secs,
        sequence_number,
        source_id,
    } = packet.header;
    let count = fit_u16(packet.flow_sets.iter().map(record_count).sum(), "count")?;

    w.u16(version);
    w.u16(count);
    w.u32(sys_uptime);
    w.u32(unix_secs);
    w.u32(sequence_number);
    w.u32(source_id);
    for flow_set in &packet.flow_sets {
        match flow_set {
            FlowSet::Templates(templates) => {
                write_flow_set(w, TEMPLATE_FLOW_SET_ID, MIN_TEMPLATE_SIZE, |w| {
                    templates.iter().try_for_each(|t| write_template(w, t))
                })?;
            }
            FlowSet::OptionsTemplates(templates) => {
                write_flow_set(
                    w,
                    OPTIONS_TEMPLATE_FLOW_SET_ID,
                    MIN_OPTIONS_TEMPLATE_SIZE,
                    |w| {
                        templates
                            .iter()
                            .try_for_each(|t| write_options_template(w, t))
                    },
                )?;
            }
            FlowSet::Data(data) => {
                let template = &data.template;
                write_data(w, template.template_id, &template.fields, &data.records)?;
            }
            FlowSet::OptionsData(data) => {
                let template = &data.template;
                let fields = [&template.scope_fields[..], &template.option_fields].concat();
                write_data(w, template.template_id, &fields, &data.records)?;
            }
            FlowSet::Unknown(_) => {}
        }
    }
    Ok(())
}

fn record_count(flow_set: &FlowSet) -> usize {
    match flow_set {
        FlowSet::Templates(templates) => templates.len(),
        FlowSet::OptionsTemplates(templates) => templates.len(),
        FlowSet::Data(data) => data.records.len(),
        FlowSet::OptionsData(data) => data.records.len(),
        FlowSet::Unknown(_) => 0,
    }
}

/// Writes a FlowSet of the records `body` writes, padded to a multiple of
/// four bytes (RFC 3954 section 5.3), unless the padding would be as long as
/// `record_size` and so read as one more record.
fn write_flow_set(
    w: &mut Writer,
    flow_set_id: u16,
    record_size: usize,
    body: impl FnOnce(&mut Writer) -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    let start = w.len();
    w.u16(flow_set_id);
    w.u16(0);
    body(w)?;
    let padding = (4 - (w.len() - start) % 4) % 4;
    if padding < record_size {
        w.zeros(padding);
    }
    let length = fit_u16(w.len() - start, "FlowSet length")?;
    w.set_u16(start + 2, length);
    Ok(())
}

fn write_template(w: &mut Writer, template: &Template) -> Result<(), WriteError> {
    w.u16(template.template_id);
    w.u16(fit_u16(template.fields.len(), "field count")?);
    template
        .fields
        .iter()
        .for_each(|field| write_field(w, field));
    Ok(())
}

fn write_options_template(w: &mut Writer, template: &OptionsTemplate) -> Result<(), WriteError> {
    let option_scope_length = fields_length(&template.scope_fields, "option scope length")?;
    let option_length = fields_length(&template.option_fields, "option length")?;
    w.u16(template.template_id);
    w.u16(option_scope_length);
    w.u16(option_length);
    template
        .scope_fields
        .iter()
        .for_each(|field| write_field(w, field));
    template
        .option_fields
        .iter()
        .for_each(|field| write_field(w, field));
    Ok(())
}

fn fields_length(fields: &[Field], name: &'static str) -> Result<u16, WriteError> {
    fit_u16(fields.len() * FIELD_SIZE, name)
}

fn write_field(w: &mut Writer, field: &Field) {
    w.u16(field.field_type);
    w.u16(field.length);
}

fn write_data(
    w: &mut Writer,
    template_id: u16,
    fields: &[Field],
    records: &[Vec<Value>],
) -> Result<(), WriteError> {
    let record_size = fields.iter().map(|field| usize::from(field.length)).sum();
    write_flow_set(w, template_id, record_size, |w| {
        for record in records {
            if record.len() != fields.len() {
                return Err(WriteError::Values {
                    values: record.len(),
                    fields: fields.len(),
                });
            }
            for (value, field) in record.iter().zip(fields) {
                encode(w, value, usize::from(field.length))?;
            }
        }
        Ok(())
    })
}
