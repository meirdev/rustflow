use num_enum::{FromPrimitive, IntoPrimitive};

use super::{FieldSpecifier, TemplateRef};
use crate::protocol::value::Value;

/// How a list's elements relate to the record holding it, numbered as in
/// IANA's IPFIX Structured Data Types Semantics registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ListSemantic {
    NoneOf = 0,
    ExactlyOneOf = 1,
    OneOrMoreOf = 2,
    AllOf = 3,
    Ordered = 4,
    #[num_enum(catch_all)]
    Unassigned(u8),
    Undefined = 255,
}

/// Values of one information element.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicList {
    pub semantic: ListSemantic,
    pub field: FieldSpecifier,
    pub values: Vec<Value>,
}

/// Records of one template.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateList {
    pub semantic: ListSemantic,
    pub records: ListRecords,
}

/// Groups of records, each group of one template.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateMultiList {
    pub semantic: ListSemantic,
    pub groups: Vec<ListRecords>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ListRecords {
    Decoded {
        template: TemplateRef,
        records: Vec<Vec<Value>>,
    },
    /// Records of a template the parser does not have, kept as sent.
    Undecoded { template_id: u16, data: Vec<u8> },
}
