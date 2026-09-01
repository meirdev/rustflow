use bytes::BufMut;
use chrono::{DateTime, Utc};

use super::parser::{
    DataRecord, FieldSpecifier, FieldValue, Header, IPFIX_HEADER_SIZE, IPFIX_VARIABLE_LENGTH,
    IpfixPacket, OptionsTemplateRecord, Record, SET_HEADER_SIZE, Set, SetHeader, TemplateRecord,
};
use crate::common::parser::NTP_UNIX_EPOCH_DIFF;

/// Convert DateTime to NTP format (two u32: seconds since 1900, fractional
/// seconds)
fn datetime_to_ntp(dt: &DateTime<Utc>) -> (u32, u32) {
    let unix_secs = dt.timestamp() as u64;
    let ntp_secs = unix_secs + NTP_UNIX_EPOCH_DIFF;
    let nanos = dt.timestamp_subsec_nanos() as u64;
    // Convert nanoseconds to NTP fractional format: nanos * 2^32 / 1_000_000_000
    let fraction = (nanos << 32) / 1_000_000_000;
    (ntp_secs as u32, fraction as u32)
}

pub trait Encode {
    fn encode<B: BufMut>(&self, buf: &mut B);
}

impl Encode for FieldSpecifier {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        let id_with_enterprise_bit = if self.enterprise_bit {
            self.information_element_identifier | 0x8000
        } else {
            self.information_element_identifier
        };
        buf.put_u16(id_with_enterprise_bit);
        buf.put_u16(self.field_length);
        if let Some(enterprise_number) = self.enterprise_number {
            buf.put_u32(enterprise_number);
        }
    }
}

impl Encode for Header {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.version);
        buf.put_u16(self.length);
        buf.put_u32(self.export_time.timestamp() as u32);
        buf.put_u32(self.sequence_number);
        buf.put_u32(self.observation_domain_id);
    }
}

impl Encode for SetHeader {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.set_id);
        buf.put_u16(self.length);
    }
}

impl Encode for TemplateRecord {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.template_id);
        buf.put_u16(self.field_count);
        for field in &self.fields {
            field.encode(buf);
        }
    }
}

impl Encode for OptionsTemplateRecord {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.template_id);
        buf.put_u16(self.field_count);
        buf.put_u16(self.scope_field_count);
        for field in &self.fields {
            field.encode(buf);
        }
    }
}

impl Encode for IpfixPacket {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        // Encode sets first to calculate total length
        let mut sets_data = Vec::new();
        for set in &self.sets {
            set.encode(&mut sets_data);
        }

        buf.put_u16(self.header.version);
        buf.put_u16(IPFIX_HEADER_SIZE as u16 + sets_data.len() as u16);
        buf.put_u32(self.header.export_time.timestamp() as u32);
        buf.put_u32(self.header.sequence_number);
        buf.put_u32(self.header.observation_domain_id);

        buf.put_slice(&sets_data);
    }
}

impl Encode for Set {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        // Encode records first to calculate length
        let mut records_data = Vec::new();
        for record in &self.records {
            record.encode(&mut records_data);
        }

        buf.put_u16(self.id);
        buf.put_u16(SET_HEADER_SIZE as u16 + records_data.len() as u16);
        buf.put_slice(&records_data);
    }
}

impl Encode for Record {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Record::Template(t) => t.encode(buf),
            Record::OptionsTemplate(t) => t.encode(buf),
            Record::Data(d) | Record::OptionsData(d) => d.encode(buf),
        }
    }
}

impl Encode for DataRecord {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        for (field, _, value) in &self.0 {
            if field.field_length == IPFIX_VARIABLE_LENGTH {
                let mut value_data = Vec::new();
                value.encode(&mut value_data);

                if value_data.len() < 255 {
                    buf.put_u8(value_data.len() as u8);
                } else {
                    buf.put_u8(255);
                    buf.put_u16(value_data.len() as u16);
                }
                buf.put_slice(&value_data);
            } else {
                value.encode(buf);
            }
        }
    }
}

impl Encode for FieldValue {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            FieldValue::Unsigned8(v) => buf.put_u8(*v),
            FieldValue::Unsigned16(v) => buf.put_u16(*v),
            FieldValue::Unsigned32(v) => buf.put_u32(*v),
            FieldValue::Unsigned64(v) => buf.put_u64(*v),
            FieldValue::Unsigned256(v) => buf.put_slice(&v.to_big_endian()),
            FieldValue::Signed8(v) => buf.put_i8(*v),
            FieldValue::Signed16(v) => buf.put_i16(*v),
            FieldValue::Signed32(v) => buf.put_i32(*v),
            FieldValue::Signed64(v) => buf.put_i64(*v),
            FieldValue::Float32(v) => buf.put_f32(*v),
            FieldValue::Float64(v) => buf.put_f64(*v),
            FieldValue::Boolean(v) => buf.put_u8(if *v { 1 } else { 2 }),
            FieldValue::MacAddress(v) => buf.put_slice(&v.as_bytes()),
            FieldValue::OctetArray(v) => buf.put_slice(v),
            FieldValue::String(v) => buf.put_slice(v.as_bytes()),
            FieldValue::DateTimeSeconds(v) => buf.put_u32(v.timestamp() as u32),
            FieldValue::DateTimeMilliseconds(v) => buf.put_u64(v.timestamp_millis() as u64),
            FieldValue::DateTimeMicroseconds(v) | FieldValue::DateTimeNanoseconds(v) => {
                // NTP format: two u32 (seconds since 1900, fractional seconds)
                let (ntp_secs, fraction) = datetime_to_ntp(v);
                buf.put_u32(ntp_secs);
                buf.put_u32(fraction);
            }
            FieldValue::Ipv4Address(v) => buf.put_slice(&v.octets()),
            FieldValue::Ipv6Address(v) => buf.put_slice(&v.octets()),
            FieldValue::BasicList(v) => {
                buf.put_u8(v.semantic.clone() as u8);
                v.field.encode(buf);
                for value in &v.content {
                    value.encode(buf);
                }
            }
            FieldValue::SubTemplateList(v) => {
                buf.put_u8(v.semantic.clone() as u8);
                buf.put_u16(v.template_id);
                for record in &v.data {
                    record.encode(buf);
                }
            }
            FieldValue::SubTemplateMultiList(v) => {
                buf.put_u8(v.semantic.clone() as u8);
                for item in &v.data {
                    buf.put_u16(item.template_id);
                    buf.put_u16(item.length);
                    for record in &item.data {
                        record.encode(buf);
                    }
                }
            }
        }
    }
}
