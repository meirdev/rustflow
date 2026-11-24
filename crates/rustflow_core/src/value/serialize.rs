use std::borrow::Cow;

use rustc_hash::FxHashMap;
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeStruct, Serializer};

use super::{ListRecords, Value};
use crate::template::{FieldSpecifier, TemplateRef};

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unsigned8(v) => serializer.serialize_u8(*v),
            Self::Unsigned16(v) => serializer.serialize_u16(*v),
            Self::Unsigned32(v) => serializer.serialize_u32(*v),
            Self::Unsigned64(v) => serializer.serialize_u64(*v),
            Self::Unsigned256(v) => serializer.serialize_str(&format!("0x{}", hex::encode(&v[..]))),
            Self::Signed8(v) => serializer.serialize_i8(*v),
            Self::Signed16(v) => serializer.serialize_i16(*v),
            Self::Signed32(v) => serializer.serialize_i32(*v),
            Self::Signed64(v) => serializer.serialize_i64(*v),
            Self::Float32(v) if v.is_finite() => serializer.serialize_f32(*v),
            Self::Float64(v) if v.is_finite() => serializer.serialize_f64(*v),
            // JSON has no form for these; RFC 7373 §4.4 writes them "NaN",
            // "+inf" and "-inf".
            Self::Float32(_) | Self::Float64(_) => match self.to_text() {
                Ok(text) => serializer.serialize_str(&text),
                Err(_) => serializer.serialize_none(),
            },
            Self::Boolean(v) => serializer.serialize_bool(*v),
            Self::MacAddress(v) => v.serialize(serializer),
            Self::OctetArray(v) => hex::serialize(v, serializer),
            Self::String(v) => serializer.serialize_str(v),
            // RFC 7373 §4.8: in UTC, without an offset.
            Self::DateTimeSeconds(_)
            | Self::DateTimeMilliseconds(_)
            | Self::DateTimeMicroseconds(_)
            | Self::DateTimeNanoseconds(_) => match self.to_text() {
                Ok(text) => serializer.serialize_str(&text),
                Err(_) => serializer.serialize_none(),
            },
            Self::Ipv4Address(v) => serializer.collect_str(v),
            Self::Ipv6Address(v) => serializer.collect_str(v),
            Self::BasicList(list) => list.serialize(serializer),
            Self::SubTemplateList(list) => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("semantic", &list.semantic)?;
                serialize_group(&mut map, &list.records)?;
                map.end()
            }
            Self::SubTemplateMultiList(list) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("semantic", &list.semantic)?;
                map.serialize_entry("groups", &Groups(&list.groups))?;
                map.end()
            }
            Self::Null => serializer.serialize_unit(),
        }
    }
}

struct Groups<'a>(&'a [ListRecords]);

impl Serialize for Groups<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(Group))
    }
}

struct Group<'a>(&'a ListRecords);

impl Serialize for Group<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        serialize_group(&mut map, self.0)?;
        map.end()
    }
}

/// The template ID and the records, or for a template the collector does
/// not have, the octets: RFC 7011 §9 has it note what it cannot read.
fn serialize_group<M: SerializeMap>(map: &mut M, group: &ListRecords) -> Result<(), M::Error> {
    match group {
        ListRecords::Decoded { template, records } => {
            map.serialize_entry("template_id", &template.template_id())?;
            let shape = Shape::new(template_keys(template));
            map.serialize_entry(
                "records",
                &Records {
                    shape: &shape,
                    records,
                },
            )
        }
        ListRecords::Undecoded { template_id, data } => {
            map.serialize_entry("template_id", template_id)?;
            map.serialize_entry("data", &hex::encode(data))
        }
    }
}

pub(crate) fn field_keys(
    fields: &[FieldSpecifier],
) -> impl Iterator<Item = Cow<'static, str>> + '_ {
    fields.iter().map(|field| field.element_id().key())
}

fn template_keys(template: &TemplateRef) -> impl Iterator<Item = Cow<'static, str>> + '_ {
    template.fields().map(|field| field.element_id().key())
}

pub(crate) fn serialize_data_set<S: Serializer>(
    serializer: S,
    template_id: u16,
    keys: impl IntoIterator<Item = Cow<'static, str>>,
    records: &[Vec<Value>],
) -> Result<S::Ok, S::Error> {
    let mut data_set = serializer.serialize_struct("DataSet", 2)?;
    data_set.serialize_field("template_id", &template_id)?;
    data_set.serialize_field(
        "records",
        &Records {
            shape: &Shape::new(keys),
            records,
        },
    )?;
    data_set.end()
}

struct Shape {
    keys: Vec<(Cow<'static, str>, Vec<usize>)>,
}

impl Shape {
    fn new(keys: impl IntoIterator<Item = Cow<'static, str>>) -> Self {
        let mut shape = Vec::<(Cow<'static, str>, Vec<usize>)>::new();
        let mut index = FxHashMap::<Cow<'static, str>, usize>::default();
        for (position, key) in keys.into_iter().enumerate() {
            match index.get(&key) {
                Some(&at) => shape[at].1.push(position),
                None => {
                    index.insert(key.clone(), shape.len());
                    shape.push((key, vec![position]));
                }
            }
        }
        Self { keys: shape }
    }
}

struct Records<'a> {
    shape: &'a Shape,
    records: &'a [Vec<Value>],
}

impl Serialize for Records<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.records.iter().map(|values| Record {
            shape: self.shape,
            values,
        }))
    }
}

struct Record<'a> {
    shape: &'a Shape,
    values: &'a [Value],
}

impl Serialize for Record<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.shape.keys.len()))?;
        for (key, positions) in &self.shape.keys {
            match positions.as_slice() {
                [position] => map.serialize_entry(key, &self.values.get(*position))?,
                positions => map.serialize_entry(
                    key,
                    &Repeated {
                        positions,
                        values: self.values,
                    },
                )?,
            }
        }
        map.end()
    }
}

struct Repeated<'a> {
    positions: &'a [usize],
    values: &'a [Value],
}

impl Serialize for Repeated<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.positions
                .iter()
                .map(|&position| self.values.get(position)),
        )
    }
}
