use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};

use crate::ie_registry::IERegistry;
use crate::types::{
    BasicList, DataRecord, FieldValue, Message, Record, Set, SubTemplateList, SubTemplateMultiItem,
    SubTemplateMultiList,
};

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

            map.serialize_entry(
                &key,
                &SerializableFieldValue {
                    value,
                    registry: self.registry,
                },
            )?;
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
