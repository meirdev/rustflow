//! The kinds of the output's columns and their values, and the fields
//! that extra fields and enrichment add to a flow.

use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use rustflow_core::common_flow::FlowType;
use rustflow_core::information_element::DataType;
use rustflow_core::mac_address::MacAddress;
use rustflow_core::value;

use crate::sink::encoder::text::Text;

/// The kind of a column's values, which is how they are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    U8,
    U16,
    U32,
    U64,
    I64,
    F64,
    Boolean,
    /// Unix time in nanoseconds.
    Timestamp,
    Text,
    FlowType,
    /// An IP address: text in its usual notation, octets in protobuf.
    Address,
    /// A MAC address: text in its usual notation, octets in protobuf.
    Mac,
    /// Text in hex, octets in protobuf.
    Octets,
}

impl Kind {
    /// The kind of an element's values; `None` for a type with no column
    /// form: lists, and unsigned256.
    pub fn of(data_type: DataType) -> Option<Self> {
        use DataType as D;
        Some(match data_type {
            D::Unsigned8 | D::Unsigned16 | D::Unsigned32 | D::Unsigned64 => Self::U64,
            D::Signed8 | D::Signed16 | D::Signed32 | D::Signed64 => Self::I64,
            D::Float32 | D::Float64 => Self::F64,
            D::Boolean => Self::Boolean,
            D::DateTimeSeconds
            | D::DateTimeMilliseconds
            | D::DateTimeMicroseconds
            | D::DateTimeNanoseconds => Self::Timestamp,
            D::Ipv4Address | D::Ipv6Address => Self::Address,
            D::MacAddress => Self::Mac,
            D::OctetArray => Self::Octets,
            D::String => Self::Text,
            _ => return None,
        })
    }

    /// The type of a field of this kind in a `.proto` file.
    pub fn proto_type(self) -> &'static str {
        match self {
            Self::U8 | Self::U16 | Self::U32 => "uint32",
            Self::U64 => "uint64",
            Self::I64 => "sint64",
            Self::F64 => "double",
            Self::Boolean => "bool",
            Self::Timestamp => "int64",
            Self::Text => "string",
            Self::FlowType => "FlowType",
            Self::Address | Self::Mac | Self::Octets => "bytes",
        }
    }

    /// The value a table holds for `text`; `None` when it is not of this
    /// kind, or the kind is not one a table column can have.
    pub fn parse(self, text: &str) -> Option<Value> {
        Some(match self {
            Self::U64 => Value::Unsigned(text.parse().ok()?),
            Self::I64 => Value::Signed(text.parse().ok()?),
            Self::F64 => Value::Float(text.parse().ok()?),
            Self::Boolean => Value::Boolean(text.parse().ok()?),
            Self::Timestamp => Value::Timestamp(text.parse().ok()?),
            Self::Text => Value::Text(text.into()),
            _ => return None,
        })
    }
}

/// The kinds a table column can be given, by name.
impl FromStr for Kind {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, ()> {
        Ok(match name {
            "string" => Self::Text,
            "unsigned" => Self::U64,
            "signed" => Self::I64,
            "float" => Self::F64,
            "boolean" => Self::Boolean,
            "timestamp" => Self::Timestamp,
            _ => return Err(()),
        })
    }
}

/// A field added to the flow, as an extra field or by enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub kind: Kind,
    /// Its protobuf field number, when given one.
    pub number: Option<u32>,
}

/// A value a table holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Boolean(bool),
    Timestamp(i64),
    Text(Arc<str>),
}

/// A column's value for one flow, as an encoder is given it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scalar<'a> {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Boolean(bool),
    Timestamp(i64),
    String(&'a str),
    FlowType(FlowType),
    Address(IpAddr),
    Mac(MacAddress),
    Octets(&'a [u8]),
}

impl<'a> Scalar<'a> {
    /// A record's value as a column of `kind`; `None` when it is not of
    /// that kind.
    pub fn of_record(value: &'a value::Value, kind: Kind) -> Option<Self> {
        use value::Value as V;
        Some(match (kind, value) {
            (Kind::U64, value) => Self::Unsigned(value.as_u64()?),
            (Kind::I64, V::Signed8(v)) => Self::Signed((*v).into()),
            (Kind::I64, V::Signed16(v)) => Self::Signed((*v).into()),
            (Kind::I64, V::Signed32(v)) => Self::Signed((*v).into()),
            (Kind::I64, V::Signed64(v)) => Self::Signed(*v),
            (Kind::F64, V::Float32(v)) => Self::Float((*v).into()),
            (Kind::F64, V::Float64(v)) => Self::Float(*v),
            (Kind::Boolean, V::Boolean(v)) => Self::Boolean(*v),
            (Kind::Timestamp, value) => {
                let nanos = value.to_timestamp()?.as_nanosecond();
                Self::Timestamp(i64::try_from(nanos).ok()?)
            }
            (Kind::Text, V::String(v)) => Self::String(v),
            (Kind::Address, V::Ipv4Address(v)) => Self::Address((*v).into()),
            (Kind::Address, V::Ipv6Address(v)) => Self::Address((*v).into()),
            (Kind::Mac, V::MacAddress(v)) => Self::Mac(*v),
            (Kind::Octets, V::OctetArray(v)) => Self::Octets(v),
            _ => return None,
        })
    }

    pub fn of_table(value: &'a Value) -> Self {
        match value {
            Value::Unsigned(v) => Self::Unsigned(*v),
            Value::Signed(v) => Self::Signed(*v),
            Value::Float(v) => Self::Float(*v),
            Value::Boolean(v) => Self::Boolean(*v),
            Value::Timestamp(v) => Self::Timestamp(*v),
            Value::Text(v) => Self::String(v),
        }
    }

    pub fn write_text(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Unsigned(v) => v.write_text(out),
            Self::Signed(v) | Self::Timestamp(v) => v.write_text(out),
            Self::Float(v) => write!(out, "{v}").expect("writing to a Vec cannot fail"),
            Self::Boolean(v) => out.extend_from_slice(if v { b"true" } else { b"false" }),
            Self::String(v) => out.extend_from_slice(v.as_bytes()),
            Self::FlowType(v) => v.write_text(out),
            Self::Address(v) => v.write_text(out),
            Self::Mac(v) => v.write_text(out),
            Self::Octets(v) => {
                for byte in v {
                    write!(out, "{byte:02x}").expect("writing to a Vec cannot fail");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: Option<Scalar<'_>>) -> Option<String> {
        let mut out = Vec::new();
        value?.write_text(&mut out);
        Some(String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_record_value_follows_the_kind_of_its_field() {
        use value::Value as V;

        let record = |value: &V, kind| text(Scalar::of_record(value, kind));
        assert_eq!(record(&V::Unsigned16(7), Kind::U64).as_deref(), Some("7"));
        assert_eq!(
            record(&V::OctetArray(vec![0xab, 0x01]), Kind::Octets).as_deref(),
            Some("ab01")
        );
        assert_eq!(
            record(&V::DateTimeSeconds(1), Kind::Timestamp).as_deref(),
            Some("1000000000")
        );
        // A value not of its field's kind is left out.
        assert_eq!(record(&V::String("x".into()), Kind::U64), None);
    }

    #[test]
    fn a_table_cell_parses_as_the_kind_of_its_column() {
        assert_eq!(Kind::U64.parse("64512"), Some(Value::Unsigned(64512)));
        assert_eq!(Kind::I64.parse("-3"), Some(Value::Signed(-3)));
        assert_eq!(Kind::Boolean.parse("true"), Some(Value::Boolean(true)));
        assert_eq!(Kind::Text.parse("a b"), Some(Value::Text("a b".into())));
        assert_eq!(Kind::U64.parse("-3"), None);
        assert_eq!(Kind::F64.parse("x"), None);
    }
}
