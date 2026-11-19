mod iana;
mod registry;

use std::borrow::Cow;
use std::fmt;
use std::ops::RangeInclusive;

pub use self::registry::{Registry, RegistryError};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[strum(serialize_all = "camelCase")]
#[repr(u8)]
#[non_exhaustive]
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

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[strum(serialize_all = "camelCase")]
#[repr(u8)]
#[non_exhaustive]
pub enum Semantic {
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

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[strum(serialize_all = "camelCase")]
#[repr(u8)]
#[non_exhaustive]
pub enum ListSemantic {
    /// None of the elements are actual properties of the Data Record.
    NoneOf = 0x00,
    /// Exactly one element is an actual property of the Data Record (XOR).
    ExactlyOneOf = 0x01,
    /// One or more elements are actual properties of the Data Record (OR).
    OneOrMoreOf = 0x02,
    /// All elements are actual properties of the Data Record.
    AllOf = 0x03,
    /// The elements are ordered.
    Ordered = 0x04,
    /// The semantic is not specified; the Collecting Process draws its own
    /// conclusions. This is the default.
    #[default]
    Undefined = 0xff,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[strum(serialize_all = "camelCase")]
#[repr(u16)]
#[non_exhaustive]
pub enum Unit {
    None = 0,
    Bits = 1,
    Octets = 2,
    Packets = 3,
    Flows = 4,
    Seconds = 5,
    Milliseconds = 6,
    Microseconds = 7,
    Nanoseconds = 8,
    #[strum(serialize = "4-octet words")]
    FourOctetWords = 9,
    Messages = 10,
    Hops = 11,
    Entries = 12,
    Frames = 13,
    Ports = 14,
    Inferred = 15,
}

impl DataType {
    pub const fn supports_semantic(self, semantic: Semantic) -> bool {
        use DataType as D;
        use Semantic as S;

        match semantic {
            S::List => matches!(
                self,
                D::BasicList | D::SubTemplateList | D::SubTemplateMultiList
            ),

            // Restrict SNMP semantics to the unsigned types corresponding to Counter32/64 and
            // Gauge32/64.
            S::SnmpCounter | S::SnmpGauge => {
                matches!(self, D::Unsigned32 | D::Unsigned64)
            }

            S::Default
            | S::Quantity
            | S::TotalCounter
            | S::DeltaCounter
            | S::Identifier
            | S::Flags => match self {
                // Apply the unsigned-integer rules to unsigned256 too.
                D::Unsigned8 | D::Unsigned16 | D::Unsigned32 | D::Unsigned64 | D::Unsigned256 => {
                    true
                }

                D::Signed8 | D::Signed16 | D::Signed32 | D::Signed64 => {
                    !matches!(semantic, S::Flags)
                }

                D::Float32 | D::Float64 => !matches!(semantic, S::Identifier | S::Flags),

                // IANA uses octetArray with flags and identifier
                D::OctetArray => matches!(semantic, S::Default | S::Identifier | S::Flags),

                D::Boolean
                | D::MacAddress
                | D::String
                | D::DateTimeSeconds
                | D::DateTimeMilliseconds
                | D::DateTimeMicroseconds
                | D::DateTimeNanoseconds
                | D::Ipv4Address
                | D::Ipv6Address => matches!(semantic, S::Default),

                D::BasicList | D::SubTemplateList | D::SubTemplateMultiList => false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementId {
    enterprise: Option<u32>,
    id: u16,
}

impl fmt::Display for ElementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.enterprise {
            None => write!(f, "({})", self.id),
            Some(enterprise) => write!(f, "({enterprise}/{})", self.id),
        }
    }
}

// The high bit of the 16-bit wire field is the enterprise flag,
// leaving 15 bits for the Information Element ID.
const MAX_ELEMENT_ID: u16 = 0x7fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidElementId(pub u16);

impl fmt::Display for InvalidElementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "element ID {} does not fit in 15 bits", self.0)
    }
}

impl std::error::Error for InvalidElementId {}

impl ElementId {
    #[cfg(feature = "serde")]
    pub(crate) fn key(self) -> Cow<'static, str> {
        match self.enterprise {
            None => iana::ELEMENTS
                .binary_search_by_key(&self.id, |&(id, ..)| id)
                .map_or_else(
                    |_| self.id.to_string().into(),
                    |index| iana::ELEMENTS[index].1.into(),
                ),
            Some(enterprise) => format!("{enterprise}/{}", self.id).into(),
        }
    }

    pub const fn new(enterprise: Option<u32>, id: u16) -> Result<Self, InvalidElementId> {
        if id > MAX_ELEMENT_ID {
            return Err(InvalidElementId(id));
        }
        Ok(Self { enterprise, id })
    }

    pub const fn try_iana(id: u16) -> Result<Self, InvalidElementId> {
        Self::new(None, id)
    }

    pub const fn try_enterprise(pen: u32, id: u16) -> Result<Self, InvalidElementId> {
        Self::new(Some(pen), id)
    }

    pub const fn enterprise(self) -> Option<u32> {
        self.enterprise
    }

    pub const fn id(self) -> u16 {
        self.id
    }

    /// Without checking that `id` fits in 15 bits, as a field specifier's
    /// does once its enterprise bit is masked off.
    pub(crate) const fn new_unchecked(enterprise: Option<u32>, id: u16) -> Self {
        Self { enterprise, id }
    }

    /// Used for the built-in IANA elements (see the `iana` module).
    pub(crate) const fn iana(id: u16) -> Self {
        match Self::try_iana(id) {
            Ok(element) => element,
            Err(_) => panic!("IANA Information Element ID exceeds 15 bits"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InformationElement {
    pub id: ElementId,
    pub name: Cow<'static, str>,
    pub data_type: DataType,
    pub semantic: Option<Semantic>,
    pub unit: Option<Unit>,
    pub range: Option<RangeInclusive<u64>>,
    pub description: Option<Cow<'static, str>>,
}

impl InformationElement {
    pub fn check(&self) -> Result<(), RegistryError> {
        match self.semantic {
            Some(semantic) if !self.data_type.supports_semantic(semantic) => {
                Err(RegistryError::UnsupportedSemantic {
                    id: self.id,
                    data_type: self.data_type,
                    semantic,
                })
            }
            _ => Ok(()),
        }
    }
}
