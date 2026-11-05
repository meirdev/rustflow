//! Information elements: what a template's field type stands for, and how
//! its values are decoded and interpreted.

use std::borrow::Cow;
use std::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};
pub use registry::Registry;

pub mod iana;
mod registry;

/// An abstract data type, numbered as in IANA's IPFIX Information Element
/// Data Types registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DataType {
    OctetArray = 0,
    Unsigned8 = 1,
    Unsigned16 = 2,
    Unsigned32 = 3,
    Unsigned64 = 4,
    Signed8 = 5,
    Signed16 = 6,
    Signed32 = 7,
    Signed64 = 8,
    Float32 = 9,
    Float64 = 10,
    Boolean = 11,
    MacAddress = 12,
    String = 13,
    DateTimeSeconds = 14,
    DateTimeMilliseconds = 15,
    DateTimeMicroseconds = 16,
    DateTimeNanoseconds = 17,
    Ipv4Address = 18,
    Ipv6Address = 19,
    BasicList = 20,
    SubTemplateList = 21,
    SubTemplateMultiList = 22,
    Unsigned256 = 23,
}

/// How a field's values are to be interpreted, numbered as in IANA's IPFIX
/// Information Element Semantics registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DataTypeSemantics {
    Default = 0,
    Quantity = 1,
    TotalCounter = 2,
    DeltaCounter = 3,
    Identifier = 4,
    Flags = 5,
    List = 6,
    SnmpCounter = 7,
    SnmpGauge = 8,
}

/// What an information element is known by: its ID, among IANA's elements
/// or a vendor's. [`iana`] has a constant for each of IANA's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElementId {
    /// The private enterprise number of a vendor's element; `None` for an
    /// IANA element.
    pub enterprise_number: Option<u32>,
    pub id: u16,
}

impl ElementId {
    pub const fn iana(id: u16) -> Self {
        Self {
            enterprise_number: None,
            id,
        }
    }
}

/// The number part of an Information Element Specifier (RFC 7013 section
/// 10.1): `(8)` for an IANA element, `(35566/403)` for a vendor's. It is a
/// partial IESpec in itself, naming the element by number alone.
impl fmt::Display for ElementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.enterprise_number {
            None => write!(f, "({})", self.id),
            Some(enterprise_number) => write!(f, "({enterprise_number}/{})", self.id),
        }
    }
}

/// An enterprise number and an ID, enterprise number 0 standing for IANA.
impl From<(u32, u16)> for ElementId {
    fn from((enterprise_number, id): (u32, u16)) -> Self {
        Self {
            enterprise_number: (enterprise_number != 0).then_some(enterprise_number),
            id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InformationElement {
    pub id: ElementId,
    pub name: Cow<'static, str>,
    pub data_type: DataType,
    pub semantics: Option<DataTypeSemantics>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_element_id_displays_as_a_partial_iespec() {
        assert_eq!(iana::SOURCE_IPV4_ADDRESS.to_string(), "(8)");
        assert_eq!(ElementId::from((35566, 403)).to_string(), "(35566/403)");
    }

    #[test]
    fn element_ids_from_pairs_take_enterprise_0_as_iana() {
        assert_eq!(ElementId::from((0, 8)), iana::SOURCE_IPV4_ADDRESS);
        assert_eq!(
            ElementId::from((9, 1)),
            ElementId {
                enterprise_number: Some(9),
                id: 1,
            }
        );
    }

    #[test]
    fn data_types_convert_from_their_iana_numbers() {
        for number in 0..=23 {
            assert_eq!(DataType::try_from(number).map(u8::from).ok(), Some(number));
        }
        assert_eq!(DataType::try_from(24).unwrap_err().number, 24);
    }
    #[test]
    fn semantics_convert_from_their_iana_numbers() {
        for number in 0..=8 {
            assert_eq!(
                DataTypeSemantics::try_from(number).map(u8::from).ok(),
                Some(number)
            );
        }
        assert_eq!(DataTypeSemantics::try_from(9).unwrap_err().number, 9);
    }
}
