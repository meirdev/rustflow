use std::sync::Arc;

use serde::Serialize;
use serde::ser::SerializeMap;

use super::ie_registry::DataType;

/// A protocol field specification with its resolved registry metadata.
#[derive(Debug, Clone)]
pub struct ResolvedField<S> {
    pub spec: S,
    pub data_type: DataType,
    pub name: Arc<str>,
}

/// Values in template order, sharing field descriptions with the template
/// cache.
#[derive(Debug, Clone)]
pub struct DataRecord<S, V> {
    fields: Arc<[ResolvedField<S>]>,
    values: Vec<V>,
}

impl<S, V> DataRecord<S, V> {
    pub fn from_template(fields: Arc<[ResolvedField<S>]>, values: Vec<V>) -> Self {
        debug_assert_eq!(fields.len(), values.len());
        Self { fields, values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn fields(&self) -> &[ResolvedField<S>] {
        &self.fields
    }

    pub fn values(&self) -> &[V] {
        &self.values
    }

    /// Each field's specification, registry name, and value, in template order.
    pub fn iter(&self) -> impl Iterator<Item = (&S, &str, &V)> {
        self.fields
            .iter()
            .zip(&self.values)
            .map(|(field, value)| (&field.spec, &*field.name, value))
    }
}

impl<S, V: Serialize> Serialize for DataRecord<S, V> {
    fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (_, key, value) in self.iter() {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}
