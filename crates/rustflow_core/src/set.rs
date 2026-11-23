use std::sync::Arc;

use crate::template::{FieldSpecifier, OptionsTemplate, Template};
use crate::value::Value;
#[cfg(feature = "serde")]
use crate::value::{field_keys, serialize_data_set};

/// A set of an IPFIX message, or a FlowSet of a NetFlow v9 packet, whose
/// options templates have scope fields of type `S`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "type",
        rename_all = "snake_case",
        bound(serialize = "S: serde::Serialize, DataSet<OptionsTemplate<S>>: serde::Serialize")
    )
)]
pub enum Set<S = FieldSpecifier> {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_templates"))]
    Templates(Vec<Arc<Template>>),
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_templates"))]
    OptionsTemplates(Vec<Arc<OptionsTemplate<S>>>),
    Data(DataSet<Template>),
    OptionsData(DataSet<OptionsTemplate<S>>),
    /// A data set whose template is not known, or does not match it.
    Undecoded {
        set_id: u16,
        #[cfg_attr(feature = "serde", serde(serialize_with = "hex::serialize"))]
        body: Vec<u8>,
    },
    /// A set of a reserved ID.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_set_id"))]
    Unknown(u16),
}

impl<S> Set<S> {
    pub fn as_data(&self) -> Option<&DataSet<Template>> {
        match self {
            Self::Data(data_set) => Some(data_set),
            _ => None,
        }
    }

    pub fn as_options_data(&self) -> Option<&DataSet<OptionsTemplate<S>>> {
        match self {
            Self::OptionsData(data_set) => Some(data_set),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataSet<T> {
    pub template: Arc<T>,
    pub records: Vec<Vec<Value>>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for DataSet<Template> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let keys = field_keys(&self.template.fields);
        serialize_data_set(serializer, self.template.template_id, keys, &self.records)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DataSet<OptionsTemplate> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let template = &self.template;
        let keys = field_keys(&template.scope_fields).chain(field_keys(&template.option_fields));
        serialize_data_set(serializer, template.template_id, keys, &self.records)
    }
}

#[cfg(feature = "serde")]
fn serialize_templates<S, T>(templates: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize + ?Sized,
{
    one_field(serializer, "templates", templates)
}

#[cfg(feature = "serde")]
fn serialize_set_id<S: serde::Serializer>(set_id: &u16, serializer: S) -> Result<S::Ok, S::Error> {
    one_field(serializer, "set_id", set_id)
}

#[cfg(feature = "serde")]
fn one_field<S, T>(serializer: S, name: &'static str, value: &T) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize + ?Sized,
{
    use serde::ser::SerializeStruct;

    let mut object = serializer.serialize_struct("Set", 1)?;
    object.serialize_field(name, value)?;
    object.end()
}
