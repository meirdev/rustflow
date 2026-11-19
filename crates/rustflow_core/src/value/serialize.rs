use std::borrow::Cow;
use std::fmt;

use rustc_hash::FxHashMap;
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct, Serializer};

use super::{ListRecords, Value};
use crate::template::{FieldSpecifier, TemplateRef};

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unsigned8(v) => serializer.serialize_u8(*v),
            Self::Unsigned16(v) => serializer.serialize_u16(*v),
            Self::Unsigned32(v) => serializer.serialize_u32(*v),
            Self::Unsigned64(v) => serializer.serialize_u64(*v),
            Self::Unsigned256(v) => serializer.collect_str(&format_args!("0x{}", Hex(&v[..]))),
            Self::Signed8(v) => serializer.serialize_i8(*v),
            Self::Signed16(v) => serializer.serialize_i16(*v),
            Self::Signed32(v) => serializer.serialize_i32(*v),
            Self::Signed64(v) => serializer.serialize_i64(*v),
            Self::Float32(v) if v.is_finite() => serializer.serialize_f32(*v),
            Self::Float64(v) if v.is_finite() => serializer.serialize_f64(*v),
            Self::Float32(_) | Self::Float64(_) => serializer.serialize_none(),
            Self::Boolean(v) => serializer.serialize_bool(*v),
            Self::MacAddress(v) => v.serialize(serializer),
            Self::OctetArray(v) => serializer.collect_str(&Hex(v)),
            Self::String(v) => serializer.serialize_str(v),
            Self::DateTimeSeconds(_) => time(serializer, self, 0),
            Self::DateTimeMilliseconds(_) => time(serializer, self, 3),
            Self::DateTimeMicroseconds(_) => time(serializer, self, 6),
            Self::DateTimeNanoseconds(_) => time(serializer, self, 9),
            Self::Ipv4Address(v) => serializer.collect_str(v),
            Self::Ipv6Address(v) => serializer.collect_str(v),
            Self::BasicList(list) => serializer.collect_seq(&list.values),
            Self::SubTemplateList(list) => match &list.records {
                ListRecords::Decoded { template, records } => Records {
                    shape: &Shape::new(template_keys(template)),
                    records,
                }
                .serialize(serializer),
                ListRecords::Undecoded { .. } => serializer.serialize_none(),
            },
            Self::SubTemplateMultiList(list) => {
                let mut seq = serializer.serialize_seq(None)?;
                for group in &list.groups {
                    match group {
                        ListRecords::Decoded { template, records } => {
                            let shape = Shape::new(template_keys(template));
                            for values in records {
                                seq.serialize_element(&Record {
                                    shape: &shape,
                                    values,
                                })?;
                            }
                        }
                        ListRecords::Undecoded { .. } => seq.serialize_element(&())?,
                    }
                }
                seq.end()
            }
            Self::Null => serializer.serialize_unit(),
        }
    }
}

fn time<S: Serializer>(serializer: S, value: &Value, precision: usize) -> Result<S::Ok, S::Error> {
    match value.to_timestamp() {
        Some(timestamp) => serializer.collect_str(&format_args!("{timestamp:.precision$}")),
        None => serializer.serialize_none(),
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

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|octet| write!(f, "{octet:02x}"))
    }
}
