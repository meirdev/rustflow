use super::Value;
use crate::information_element::ListSemantic;
use crate::template::{FieldSpecifier, TemplateRef};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BasicList {
    pub semantic: ListSemantic,
    pub field: FieldSpecifier,
    pub values: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SubTemplateList {
    pub semantic: ListSemantic,
    pub records: ListRecords,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SubTemplateMultiList {
    pub semantic: ListSemantic,
    pub groups: Vec<ListRecords>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ListRecords {
    Decoded {
        template: TemplateRef,
        records: Vec<Vec<Value>>,
    },
    Undecoded {
        template_id: u16,
        data: Vec<u8>,
    },
}
