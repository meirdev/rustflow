use super::Value;
use crate::bytes::Writer;
use crate::protocol::WriteError;

/// Writes a value as a field of `length` bytes, the reverse of
/// [`decode`](super::decode). An integer may take fewer bytes than its type,
/// if it fits (RFC 7011 section 6.2), or more; a string is padded with
/// trailing NULs, and `Null` is written as zeros. A value that does not fit,
/// or has no encoding of that length, is an error, as is a list: only
/// IPFIX encodes lists, with its templates.
pub(crate) fn encode(w: &mut Writer, value: &Value, length: usize) -> Result<(), WriteError> {
    let does_not_fit = Err(WriteError::DoesNotFit { length });
    match value {
        Value::Unsigned8(v) => unsigned(w, &v.to_be_bytes(), length),
        Value::Unsigned16(v) => unsigned(w, &v.to_be_bytes(), length),
        Value::Unsigned32(v) => unsigned(w, &v.to_be_bytes(), length),
        Value::Unsigned64(v) => unsigned(w, &v.to_be_bytes(), length),
        Value::Unsigned256(v) => unsigned(w, v.as_slice(), length),
        Value::Signed8(v) => signed(w, i64::from(*v), length),
        Value::Signed16(v) => signed(w, i64::from(*v), length),
        Value::Signed32(v) => signed(w, i64::from(*v), length),
        Value::Signed64(v) => signed(w, *v, length),
        Value::Float32(v) => match length {
            4 => exact(w, &v.to_be_bytes(), length),
            8 => exact(w, &f64::from(*v).to_be_bytes(), length),
            _ => does_not_fit,
        },
        Value::Float64(v) => match length {
            8 => exact(w, &v.to_be_bytes(), length),
            4 if f64::from(*v as f32) == *v => exact(w, &(*v as f32).to_be_bytes(), length),
            _ => does_not_fit,
        },
        Value::Boolean(v) => exact(w, &[if *v { 1 } else { 2 }], length),
        Value::MacAddress(v) => exact(w, v, length),
        Value::OctetArray(v) => exact(w, v, length),
        Value::String(v) if v.len() <= length => {
            w.bytes(v.as_bytes());
            w.zeros(length - v.len());
            Ok(())
        }
        Value::DateTimeSeconds(v) => exact(w, &v.to_be_bytes(), length),
        Value::DateTimeMilliseconds(v) => exact(w, &v.to_be_bytes(), length),
        Value::DateTimeMicroseconds(v) | Value::DateTimeNanoseconds(v) => {
            let [s0, s1, s2, s3] = v.seconds.to_be_bytes();
            let [f0, f1, f2, f3] = v.fraction.to_be_bytes();
            exact(w, &[s0, s1, s2, s3, f0, f1, f2, f3], length)
        }
        Value::Ipv4Address(v) => exact(w, &v.octets(), length),
        Value::Ipv6Address(v) => exact(w, &v.octets(), length),
        Value::Null => {
            w.zeros(length);
            Ok(())
        }
        Value::String(_)
        | Value::BasicList(_)
        | Value::SubTemplateList(_)
        | Value::SubTemplateMultiList(_) => does_not_fit,
    }
}

/// The length a value takes in a field of no fixed length: its type's
/// width, or its own for an octet array or a string. `None` for a list,
/// whose length is known only once written.
pub fn natural_length(value: &Value) -> Option<usize> {
    let length = match value {
        Value::Null => 0,
        Value::Unsigned8(_) | Value::Signed8(_) | Value::Boolean(_) => 1,
        Value::Unsigned16(_) | Value::Signed16(_) => 2,
        Value::Unsigned32(_)
        | Value::Signed32(_)
        | Value::Float32(_)
        | Value::DateTimeSeconds(_)
        | Value::Ipv4Address(_) => 4,
        Value::MacAddress(_) => 6,
        Value::Unsigned64(_)
        | Value::Signed64(_)
        | Value::Float64(_)
        | Value::DateTimeMilliseconds(_)
        | Value::DateTimeMicroseconds(_)
        | Value::DateTimeNanoseconds(_) => 8,
        Value::Ipv6Address(_) => 16,
        Value::Unsigned256(_) => 32,
        Value::OctetArray(bytes) => bytes.len(),
        Value::String(string) => string.len(),
        Value::BasicList(_) | Value::SubTemplateList(_) | Value::SubTemplateMultiList(_) => {
            return None;
        }
    };
    Some(length)
}

fn exact(w: &mut Writer, bytes: &[u8], length: usize) -> Result<(), WriteError> {
    if bytes.len() != length {
        return Err(WriteError::DoesNotFit { length });
    }
    w.bytes(bytes);
    Ok(())
}

/// A big-endian unsigned integer in 1 to 32 bytes, the lengths
/// [`decode`](super::decode) reads one from: leading zeros dropped, or
/// added.
fn unsigned(w: &mut Writer, bytes: &[u8], length: usize) -> Result<(), WriteError> {
    if !(1..=32).contains(&length) {
        return Err(WriteError::DoesNotFit { length });
    }
    match bytes.len().checked_sub(length) {
        Some(dropped) if bytes[..dropped].iter().all(|&b| b == 0) => w.bytes(&bytes[dropped..]),
        Some(_) => return Err(WriteError::DoesNotFit { length }),
        None => {
            w.zeros(length - bytes.len());
            w.bytes(bytes);
        }
    }
    Ok(())
}

/// A big-endian signed integer in 1 to 8 bytes, if it keeps its value
/// sign-extended from there.
fn signed(w: &mut Writer, value: i64, length: usize) -> Result<(), WriteError> {
    if !(1..=8).contains(&length) {
        return Err(WriteError::DoesNotFit { length });
    }
    let shift = 8 * (8 - length);
    if (value << shift) >> shift != value {
        return Err(WriteError::DoesNotFit { length });
    }
    w.bytes(&value.to_be_bytes()[8 - length..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::protocol::information_element::DataType;
    use crate::protocol::value::{NtpTimestamp, decode};

    fn encoded(value: &Value, length: usize) -> Result<Vec<u8>, WriteError> {
        let mut buf = Vec::new();
        encode(&mut Writer::new(&mut buf), value, length).map(|()| buf)
    }

    #[test]
    fn values_decode_back_from_what_they_encode_to() {
        let ntp = NtpTimestamp {
            seconds: 0xe90e_5b00,
            fraction: 0x8000_0001,
        };
        for (data_type, value, length) in [
            (DataType::Unsigned8, Value::Unsigned8(7), 1),
            (DataType::Unsigned16, Value::Unsigned16(0x0102), 2),
            (DataType::Unsigned32, Value::Unsigned32(0x0102_0304), 4),
            (DataType::Unsigned64, Value::Unsigned64(u64::MAX), 8),
            (
                DataType::Unsigned256,
                Value::Unsigned256(Box::new([0xab; 32])),
                32,
            ),
            (DataType::Signed8, Value::Signed8(-1), 1),
            (DataType::Signed16, Value::Signed16(-2), 2),
            (DataType::Signed32, Value::Signed32(i32::MIN), 4),
            (DataType::Signed64, Value::Signed64(i64::MIN), 8),
            (DataType::Float32, Value::Float32(1.5), 4),
            (DataType::Float64, Value::Float64(-2.5), 8),
            (DataType::Boolean, Value::Boolean(true), 1),
            (DataType::Boolean, Value::Boolean(false), 1),
            (
                DataType::MacAddress,
                Value::MacAddress([1, 2, 3, 4, 5, 6]),
                6,
            ),
            (DataType::OctetArray, Value::OctetArray(vec![1, 2, 3]), 3),
            (DataType::String, Value::String("eth0".to_owned()), 4),
            (
                DataType::DateTimeSeconds,
                Value::DateTimeSeconds(1_700_000_000),
                4,
            ),
            (
                DataType::DateTimeMilliseconds,
                Value::DateTimeMilliseconds(1_700_000_000_123),
                8,
            ),
            (
                DataType::DateTimeMicroseconds,
                Value::DateTimeMicroseconds(ntp),
                8,
            ),
            (
                DataType::DateTimeNanoseconds,
                Value::DateTimeNanoseconds(ntp),
                8,
            ),
            (
                DataType::Ipv4Address,
                Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
                4,
            ),
            (
                DataType::Ipv6Address,
                Value::Ipv6Address(Ipv6Addr::LOCALHOST),
                16,
            ),
        ] {
            let bytes = encoded(&value, length).unwrap();
            assert_eq!(decode(data_type, &bytes), value, "{value:?}");
        }
    }

    #[test]
    fn integers_take_as_many_bytes_as_the_field_if_they_fit() {
        assert_eq!(encoded(&Value::Unsigned64(0x0102), 2), Ok(vec![1, 2]));
        assert_eq!(encoded(&Value::Unsigned8(1), 3), Ok(vec![0, 0, 1]));
        assert_eq!(
            encoded(&Value::Unsigned64(1), 16),
            Ok([vec![0; 15], vec![1]].concat())
        );
        assert_eq!(encoded(&Value::Signed64(-2), 3), Ok(vec![0xff, 0xff, 0xfe]));
        assert_eq!(
            encoded(&Value::Signed16(-2), 4),
            Ok(vec![0xff, 0xff, 0xff, 0xfe])
        );
        assert_eq!(encoded(&Value::Signed32(0x7f), 1), Ok(vec![0x7f]));

        let mut wide = [0; 32];
        wide[31] = 9;
        assert_eq!(encoded(&Value::Unsigned256(Box::new(wide)), 1), Ok(vec![9]));
    }

    #[test]
    fn integers_that_do_not_fit_are_errors() {
        let does_not_fit = |length| Err(WriteError::DoesNotFit { length });
        assert_eq!(encoded(&Value::Unsigned32(0x1_0000), 2), does_not_fit(2));
        assert_eq!(encoded(&Value::Unsigned8(1), 0), does_not_fit(0));
        assert_eq!(encoded(&Value::Unsigned8(1), 33), does_not_fit(33));
        assert_eq!(encoded(&Value::Signed32(128), 1), does_not_fit(1));
        assert_eq!(encoded(&Value::Signed32(-129), 1), does_not_fit(1));
        assert_eq!(encoded(&Value::Signed8(-1), 9), does_not_fit(9));
    }

    #[test]
    fn floats_narrow_only_without_loss() {
        assert_eq!(
            encoded(&Value::Float32(1.5), 8),
            Ok(1.5f64.to_be_bytes().to_vec())
        );
        assert_eq!(
            encoded(&Value::Float64(1.5), 4),
            Ok(1.5f32.to_be_bytes().to_vec())
        );
        assert_eq!(
            encoded(&Value::Float64(0.1), 4),
            Err(WriteError::DoesNotFit { length: 4 })
        );
    }

    #[test]
    fn strings_are_padded_with_nuls_but_not_cut() {
        assert_eq!(
            encoded(&Value::String("ab".to_owned()), 4),
            Ok(b"ab\0\0".to_vec())
        );
        assert_eq!(
            encoded(&Value::String("abc".to_owned()), 2),
            Err(WriteError::DoesNotFit { length: 2 })
        );
    }

    #[test]
    fn fixed_size_values_need_their_exact_length() {
        for value in [
            Value::OctetArray(vec![1, 2]),
            Value::MacAddress([0; 6]),
            Value::Boolean(true),
            Value::DateTimeSeconds(0),
            Value::Ipv4Address(Ipv4Addr::LOCALHOST),
        ] {
            assert_eq!(
                encoded(&value, 7),
                Err(WriteError::DoesNotFit { length: 7 }),
                "{value:?}"
            );
        }
    }

    #[test]
    fn values_encode_at_their_natural_length() {
        for value in [
            Value::Unsigned16(7),
            Value::Signed64(-1),
            Value::Unsigned256(Box::new([1; 32])),
            Value::MacAddress([1; 6]),
            Value::OctetArray(vec![1, 2, 3]),
            Value::String("eth0".to_owned()),
            Value::Ipv6Address(Ipv6Addr::LOCALHOST),
            Value::Null,
        ] {
            let length = natural_length(&value).unwrap();
            assert_eq!(
                encoded(&value, length).map(|b| b.len()),
                Ok(length),
                "{value:?}"
            );
        }
    }

    #[test]
    fn null_is_written_as_zeros() {
        assert_eq!(encoded(&Value::Null, 3), Ok(vec![0, 0, 0]));
    }
}
