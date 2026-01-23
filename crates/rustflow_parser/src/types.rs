use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use primitive_types::U256;
use rustc_hash::FxHashMap;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use serde::Serialize;

use crate::ie_registry::IERegistry;

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub version: u16,
    pub length: u16,
    pub export_time: DateTime<Utc>,
    pub sequence_number: u32,
    pub observation_domain_id: u32,

    // NetFlow V5 & V9
    pub count: u16,
    pub system_uptime: Option<DateTime<Utc>>,

    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Set {
    pub set_id: u16,
    pub length: u16,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Record {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: bool,
    pub information_element_identifier: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecord(pub FxHashMap<(u32, u16), FieldValue>);

#[derive(Debug, Clone, Serialize)]
pub enum FieldValue {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Unsigned256(U256),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress(MacAddr6),
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(DateTime<Utc>),
    DateTimeMilliseconds(DateTime<Utc>),
    DateTimeMicroseconds(DateTime<Utc>),
    DateTimeNanoseconds(DateTime<Utc>),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(BasicList),
    SubTemplateList(SubTemplateList),
    SubTemplateMultiList(SubTemplateMultiList),
}

#[repr(u8)]
#[derive(Debug, Clone, Serialize)]
pub enum Semantic {
    NoneOf = 0x00,
    ExactlyOneOf = 0x01,
    OneOrMoreOf = 0x02,
    AllOf = 0x03,
    Ordered = 0x04,
    Undefined = 0xff,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicList {
    pub semantic: Semantic,
    pub field: FieldSpecifier,
    pub content: Vec<FieldValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateList {
    pub semantic: Semantic,
    pub template_id: u16,
    pub data: Vec<DataRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiList {
    pub semantic: Semantic,
    pub data: Vec<SubTemplateMultiItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiItem {
    pub template_id: u16,
    pub length: u16,
    pub data: Vec<DataRecord>,
}

impl TryFrom<u8> for Semantic {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Semantic::NoneOf),
            0x01 => Ok(Semantic::ExactlyOneOf),
            0x02 => Ok(Semantic::OneOrMoreOf),
            0x03 => Ok(Semantic::AllOf),
            0x04 => Ok(Semantic::Ordered),
            0xff => Ok(Semantic::Undefined),
            _ => Err(()),
        }
    }
}

impl Display for Semantic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Semantic::NoneOf => write!(f, "noneOf"),
            Semantic::ExactlyOneOf => write!(f, "exactlyOneOf"),
            Semantic::OneOrMoreOf => write!(f, "oneOrMoreOf"),
            Semantic::AllOf => write!(f, "allOf"),
            Semantic::Ordered => write!(f, "ordered"),
            Semantic::Undefined => write!(f, "undefined"),
        }
    }
}

impl Display for FieldValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FieldValue::Unsigned8(v) => write!(f, "{}", v),
            FieldValue::Unsigned16(v) => write!(f, "{}", v),
            FieldValue::Unsigned32(v) => write!(f, "{}", v),
            FieldValue::Unsigned64(v) => write!(f, "{}", v),
            FieldValue::Unsigned256(v) => write!(f, "{}", v),
            FieldValue::Signed8(v) => write!(f, "{}", v),
            FieldValue::Signed16(v) => write!(f, "{}", v),
            FieldValue::Signed32(v) => write!(f, "{}", v),
            FieldValue::Signed64(v) => write!(f, "{}", v),
            FieldValue::Float32(v) => write!(f, "{}", v),
            FieldValue::Float64(v) => write!(f, "{}", v),
            FieldValue::Boolean(v) => write!(f, "{}", v),
            FieldValue::MacAddress(v) => write!(f, "{}", v),
            FieldValue::OctetArray(v) => write!(f, "{}", hex::encode(v)),
            FieldValue::String(v) => write!(f, "{}", v),
            FieldValue::DateTimeSeconds(v) => write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S")),
            FieldValue::DateTimeMilliseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%3f"))
            }
            FieldValue::DateTimeMicroseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%6f"))
            }
            FieldValue::DateTimeNanoseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%9f"))
            }
            FieldValue::Ipv4Address(v) => write!(f, "{}", v),
            FieldValue::Ipv6Address(v) => write!(f, "{}", v),
            // There is no RFC for this:
            FieldValue::BasicList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateMultiList(v) => write!(f, "{:?}", v),
        }
    }
}

pub struct SerializableMessage<'a> {
    pub message: &'a Message,
    pub registry: &'a IERegistry,
}

impl<'a> SerializableMessage<'a> {
    pub fn new(message: &'a Message, registry: &'a IERegistry) -> Self {
        Self { message, registry }
    }
}

impl Serialize for SerializableMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Message", 6)?;
        state.serialize_field("version", &self.message.version)?;
        state.serialize_field("length", &self.message.length)?;
        state.serialize_field("export_time", &self.message.export_time)?;
        state.serialize_field("sequence_number", &self.message.sequence_number)?;
        state.serialize_field("observation_domain_id", &self.message.observation_domain_id)?;
        state.serialize_field(
            "sets",
            &SerializableSets {
                sets: &self.message.sets,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}

struct SerializableSets<'a> {
    sets: &'a Vec<Set>,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSets<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.sets.len()))?;
        for set in self.sets {
            seq.serialize_element(&SerializableSet {
                set,
                registry: self.registry,
            })?;
        }
        seq.end()
    }
}

struct SerializableSet<'a> {
    set: &'a Set,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSet<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Set", 3)?;
        state.serialize_field("set_id", &self.set.set_id)?;
        state.serialize_field("length", &self.set.length)?;
        state.serialize_field(
            "records",
            &SerializableRecords {
                records: &self.set.records,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}

struct SerializableRecords<'a> {
    records: &'a Vec<Record>,
    registry: &'a IERegistry,
}

impl Serialize for SerializableRecords<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for record in self.records {
            seq.serialize_element(&SerializableRecord {
                record,
                registry: self.registry,
            })?;
        }
        seq.end()
    }
}

struct SerializableRecord<'a> {
    record: &'a Record,
    registry: &'a IERegistry,
}

impl Serialize for SerializableRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.record {
            Record::Template(t) => {
                let mut state = serializer.serialize_struct("Record", 1)?;
                state.serialize_field("Template", t)?;
                state.end()
            }
            Record::OptionsTemplate(t) => {
                let mut state = serializer.serialize_struct("Record", 1)?;
                state.serialize_field("OptionsTemplate", t)?;
                state.end()
            }
            Record::Data(d) => {
                let mut state = serializer.serialize_struct("Record", 1)?;
                state.serialize_field(
                    "Data",
                    &SerializableDataRecord {
                        record: d,
                        registry: self.registry,
                    },
                )?;
                state.end()
            }
        }
    }
}

pub struct SerializableDataRecord<'a> {
    pub record: &'a DataRecord,
    pub registry: &'a IERegistry,
}

impl<'a> SerializableDataRecord<'a> {
    pub fn new(record: &'a DataRecord, registry: &'a IERegistry) -> Self {
        Self { record, registry }
    }
}

impl Serialize for SerializableDataRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.record.0.len()))?;

        for ((enterprise_number, element_id), value) in &self.record.0 {
            let enterprise_opt = if *enterprise_number == 0 {
                None
            } else {
                Some(*enterprise_number)
            };

            let key = match self.registry.lookup(*element_id, enterprise_opt) {
                Some(def) => def.name.clone(),
                None => {
                    if *enterprise_number == 0 {
                        format!("unknown_{}", element_id)
                    } else {
                        format!("{}:{}", enterprise_number, element_id)
                    }
                }
            };

            map.serialize_entry(&key, &SerializableFieldValue {
                value,
                registry: self.registry,
            })?;
        }

        map.end()
    }
}

struct SerializableFieldValue<'a> {
    value: &'a FieldValue,
    registry: &'a IERegistry,
}

impl Serialize for SerializableFieldValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.value {
            // Primitives - serialize the inner value directly
            FieldValue::Unsigned8(v) => serializer.serialize_u8(*v),
            FieldValue::Unsigned16(v) => serializer.serialize_u16(*v),
            FieldValue::Unsigned32(v) => serializer.serialize_u32(*v),
            FieldValue::Unsigned64(v) => serializer.serialize_u64(*v),
            FieldValue::Unsigned256(v) => v.serialize(serializer),
            FieldValue::Signed8(v) => serializer.serialize_i8(*v),
            FieldValue::Signed16(v) => serializer.serialize_i16(*v),
            FieldValue::Signed32(v) => serializer.serialize_i32(*v),
            FieldValue::Signed64(v) => serializer.serialize_i64(*v),
            FieldValue::Float32(v) => serializer.serialize_f32(*v),
            FieldValue::Float64(v) => serializer.serialize_f64(*v),
            FieldValue::Boolean(v) => serializer.serialize_bool(*v),
            FieldValue::String(v) => serializer.serialize_str(v),

            // Types with their own Serialize impl - delegate directly
            FieldValue::MacAddress(v) => v.serialize(serializer),
            FieldValue::Ipv4Address(v) => v.serialize(serializer),
            FieldValue::Ipv6Address(v) => v.serialize(serializer),
            FieldValue::DateTimeSeconds(v) => v.serialize(serializer),
            FieldValue::DateTimeMilliseconds(v) => v.serialize(serializer),
            FieldValue::DateTimeMicroseconds(v) => v.serialize(serializer),
            FieldValue::DateTimeNanoseconds(v) => v.serialize(serializer),

            // OctetArray as hex string
            FieldValue::OctetArray(v) => serializer.serialize_str(&hex::encode(v)),

            // Nested structures that contain DataRecord - pass the registry
            FieldValue::BasicList(list) => SerializableBasicList {
                list,
                registry: self.registry,
            }
            .serialize(serializer),
            FieldValue::SubTemplateList(list) => SerializableSubTemplateList {
                list,
                registry: self.registry,
            }
            .serialize(serializer),
            FieldValue::SubTemplateMultiList(list) => SerializableSubTemplateMultiList {
                list,
                registry: self.registry,
            }
            .serialize(serializer),
        }
    }
}

struct SerializableBasicList<'a> {
    list: &'a BasicList,
    registry: &'a IERegistry,
}

impl Serialize for SerializableBasicList<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BasicList", 3)?;
        state.serialize_field("semantic", &self.list.semantic)?;
        state.serialize_field("field", &self.list.field)?;
        state.serialize_field(
            "content",
            &SerializableFieldValues {
                values: &self.list.content,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}

struct SerializableFieldValues<'a> {
    values: &'a Vec<FieldValue>,
    registry: &'a IERegistry,
}

impl Serialize for SerializableFieldValues<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.values.len()))?;
        for value in self.values {
            seq.serialize_element(&SerializableFieldValue {
                value,
                registry: self.registry,
            })?;
        }
        seq.end()
    }
}

struct SerializableSubTemplateList<'a> {
    list: &'a SubTemplateList,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSubTemplateList<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SubTemplateList", 3)?;
        state.serialize_field("semantic", &self.list.semantic)?;
        state.serialize_field("template_id", &self.list.template_id)?;
        state.serialize_field(
            "data",
            &SerializableDataRecords {
                records: &self.list.data,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}

struct SerializableDataRecords<'a> {
    records: &'a Vec<DataRecord>,
    registry: &'a IERegistry,
}

impl Serialize for SerializableDataRecords<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for record in self.records {
            seq.serialize_element(&SerializableDataRecord {
                record,
                registry: self.registry,
            })?;
        }
        seq.end()
    }
}

struct SerializableSubTemplateMultiList<'a> {
    list: &'a SubTemplateMultiList,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSubTemplateMultiList<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SubTemplateMultiList", 2)?;
        state.serialize_field("semantic", &self.list.semantic)?;
        state.serialize_field(
            "data",
            &SerializableSubTemplateMultiItems {
                items: &self.list.data,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}

struct SerializableSubTemplateMultiItems<'a> {
    items: &'a Vec<SubTemplateMultiItem>,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSubTemplateMultiItems<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.items.len()))?;
        for item in self.items {
            seq.serialize_element(&SerializableSubTemplateMultiItem {
                item,
                registry: self.registry,
            })?;
        }
        seq.end()
    }
}

struct SerializableSubTemplateMultiItem<'a> {
    item: &'a SubTemplateMultiItem,
    registry: &'a IERegistry,
}

impl Serialize for SerializableSubTemplateMultiItem<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SubTemplateMultiItem", 3)?;
        state.serialize_field("template_id", &self.item.template_id)?;
        state.serialize_field("length", &self.item.length)?;
        state.serialize_field(
            "data",
            &SerializableDataRecords {
                records: &self.item.data,
                registry: self.registry,
            },
        )?;
        state.end()
    }
}
