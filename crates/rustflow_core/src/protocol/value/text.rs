use serde::{Serialize, Serializer};

use super::Value;

/// A value as RFC 7373 represents it in an enclosing format such as JSON.
///
/// Integers, finite floats and booleans take the format's own
/// representation, as RFC 7373 recommends where the format has one
/// (sections 4.2 to 4.5), and strings are the format's strings. Other
/// values are strings of their textual form, as the value's `Display`
/// writes it; so are the floats `NaN`, `+inf` and `-inf`, which JSON
/// numbers cannot express. Lists and `Null`, which have no textual form,
/// are serialized as none.
#[derive(Debug, Clone, Copy)]
pub struct Text<'a>(pub &'a Value);

impl Serialize for Text<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self.0 {
            Value::Unsigned8(v) => serializer.serialize_u8(v),
            Value::Unsigned16(v) => serializer.serialize_u16(v),
            Value::Unsigned32(v) => serializer.serialize_u32(v),
            Value::Unsigned64(v) => serializer.serialize_u64(v),
            Value::Signed8(v) => serializer.serialize_i8(v),
            Value::Signed16(v) => serializer.serialize_i16(v),
            Value::Signed32(v) => serializer.serialize_i32(v),
            Value::Signed64(v) => serializer.serialize_i64(v),
            Value::Float32(v) if v.is_finite() => serializer.serialize_f32(v),
            Value::Float64(v) if v.is_finite() => serializer.serialize_f64(v),
            Value::Boolean(v) => serializer.serialize_bool(v),
            Value::String(ref v) => serializer.serialize_str(v),
            Value::BasicList(_)
            | Value::SubTemplateList(_)
            | Value::SubTemplateMultiList(_)
            | Value::Null => serializer.serialize_none(),
            ref value => serializer.collect_str(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use serde_json::{Value as Json, json};

    use super::*;
    use crate::protocol::ipfix::{BasicList, FieldSpecifier, ListSemantic};

    fn json(value: Value) -> Json {
        serde_json::to_value(Text(&value)).unwrap()
    }

    #[test]
    fn numbers_and_booleans_are_the_formats_own() {
        assert_eq!(json(Value::Unsigned64(u64::MAX)), json!(u64::MAX));
        assert_eq!(json(Value::Signed8(-5)), json!(-5));
        assert_eq!(json(Value::Float64(1.5)), json!(1.5));
        assert_eq!(json(Value::Boolean(true)), json!(true));
        assert_eq!(json(Value::String("a \"b\"".into())), json!("a \"b\""));
    }

    #[test]
    fn floats_json_cannot_express_are_strings() {
        assert_eq!(json(Value::Float64(f64::NAN)), json!("NaN"));
        assert_eq!(json(Value::Float32(f32::INFINITY)), json!("+inf"));
        assert_eq!(json(Value::Float64(f64::NEG_INFINITY)), json!("-inf"));
    }

    #[test]
    fn other_values_are_strings_of_their_textual_form() {
        assert_eq!(
            json(Value::DateTimeMilliseconds(1_352_140_261_135)),
            json!("2012-11-05T18:31:01.135")
        );
        assert_eq!(
            json(Value::Ipv6Address(Ipv6Addr::new(
                0x2001, 0xdb8, 0xc, 0x1337, 0, 0, 0, 2
            ))),
            json!("2001:db8:c:1337::2")
        );
        assert_eq!(
            json(Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))),
            json!("192.0.2.1")
        );
        assert_eq!(
            json(Value::MacAddress([2, 0, 0, 0, 0, 0xab])),
            json!("02:00:00:00:00:ab")
        );
        assert_eq!(json(Value::OctetArray(vec![0xde, 0xad])), json!("dead"));
        let mut unsigned256 = [0; 32];
        unsigned256[31] = 0xff;
        assert_eq!(
            json(Value::Unsigned256(Box::new(unsigned256))),
            json!("0xff")
        );
    }

    #[test]
    fn values_without_a_textual_form_are_none() {
        let list = Value::BasicList(Box::new(BasicList {
            semantic: ListSemantic::AllOf,
            field: FieldSpecifier {
                information_element_id: 8,
                field_length: 4,
                enterprise_number: None,
            },
            values: Vec::new(),
        }));
        assert_eq!(json(list), Json::Null);
        assert_eq!(json(Value::Null), Json::Null);
    }
}
