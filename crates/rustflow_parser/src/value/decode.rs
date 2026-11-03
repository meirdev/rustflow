use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use super::{NtpTimestamp, Value};
use crate::information_element::DataType;

/// Decodes a field from exactly its bytes. A length the data type has no
/// encoding for keeps the bytes as an octet array, as do lists.
///
/// Integers and floats are read at the field's length rather than the
/// width their data type names, since exporters may send them in fewer
/// bytes (RFC 7011 section 6.2).
pub fn decode(data_type: DataType, bytes: &[u8]) -> Value {
    decode_exact(data_type, bytes).unwrap_or_else(|| Value::OctetArray(bytes.to_vec()))
}

fn decode_exact(data_type: DataType, bytes: &[u8]) -> Option<Value> {
    let value = match data_type {
        DataType::Unsigned8
        | DataType::Unsigned16
        | DataType::Unsigned32
        | DataType::Unsigned64
        | DataType::Unsigned256 => unsigned(bytes)?,
        DataType::Signed8 | DataType::Signed16 | DataType::Signed32 | DataType::Signed64 => {
            signed(bytes)?
        }
        DataType::Float32 | DataType::Float64 => match bytes.len() {
            4 => Value::Float32(f32::from_be_bytes(exact(bytes)?)),
            8 => Value::Float64(f64::from_be_bytes(exact(bytes)?)),
            _ => return None,
        },
        DataType::Boolean => match exact(bytes)? {
            [1] => Value::Boolean(true),
            [2] => Value::Boolean(false),
            _ => Value::Null,
        },
        DataType::MacAddress => Value::MacAddress(exact(bytes)?),
        // A fixed-length string is padded with trailing NULs, which are not
        // part of the value.
        DataType::String => from_utf8(bytes).map_or(Value::Null, |s| {
            Value::String(s.trim_end_matches('\0').to_owned())
        }),
        DataType::DateTimeSeconds => Value::DateTimeSeconds(u32::from_be_bytes(exact(bytes)?)),
        DataType::DateTimeMilliseconds => {
            Value::DateTimeMilliseconds(u64::from_be_bytes(exact(bytes)?))
        }
        DataType::DateTimeMicroseconds => Value::DateTimeMicroseconds(ntp_timestamp(bytes)?),
        DataType::DateTimeNanoseconds => Value::DateTimeNanoseconds(ntp_timestamp(bytes)?),
        DataType::Ipv4Address => Value::Ipv4Address(Ipv4Addr::from(exact::<4>(bytes)?)),
        DataType::Ipv6Address => Value::Ipv6Address(Ipv6Addr::from(exact::<16>(bytes)?)),
        DataType::OctetArray
        | DataType::BasicList
        | DataType::SubTemplateList
        | DataType::SubTemplateMultiList => return None,
    };
    Some(value)
}

fn exact<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn ntp_timestamp(bytes: &[u8]) -> Option<NtpTimestamp> {
    let [s0, s1, s2, s3, f0, f1, f2, f3] = exact(bytes)?;
    Some(NtpTimestamp {
        seconds: u32::from_be_bytes([s0, s1, s2, s3]),
        fraction: u32::from_be_bytes([f0, f1, f2, f3]),
    })
}

fn unsigned(bytes: &[u8]) -> Option<Value> {
    let value = match bytes.len() {
        1 => Value::Unsigned8(u8::try_from(uint(bytes)).ok()?),
        2 => Value::Unsigned16(u16::try_from(uint(bytes)).ok()?),
        3 | 4 => Value::Unsigned32(u32::try_from(uint(bytes)).ok()?),
        5..=8 => Value::Unsigned64(uint(bytes)),
        9..=32 => {
            let mut value = [0; 32];
            value[32 - bytes.len()..].copy_from_slice(bytes);
            Value::Unsigned256(Box::new(value))
        }
        _ => return None,
    };
    Some(value)
}

fn signed(bytes: &[u8]) -> Option<Value> {
    let value = match bytes.len() {
        1 => Value::Signed8(i8::try_from(int(bytes)).ok()?),
        2 => Value::Signed16(i16::try_from(int(bytes)).ok()?),
        3 | 4 => Value::Signed32(i32::try_from(int(bytes)).ok()?),
        5..=8 => Value::Signed64(int(bytes)),
        _ => return None,
    };
    Some(value)
}
/// A big-endian unsigned integer of 1 to 8 bytes.
fn uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b))
}

/// A big-endian signed integer of 1 to 8 bytes, sign-extended from its top
/// bit.
fn int(bytes: &[u8]) -> i64 {
    let shift = 8 * (8 - bytes.len());
    (uint(bytes).cast_signed() << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsigned_integers_of_every_size() {
        let unsigned = |bytes: &[u8]| decode(DataType::Unsigned64, bytes);
        assert_eq!(unsigned(&[0x01]), Value::Unsigned8(0x01));
        assert_eq!(unsigned(&[0x01, 0x02]), Value::Unsigned16(0x0102));
        assert_eq!(unsigned(&[0x01, 0x02, 0x03]), Value::Unsigned32(0x01_0203));
        assert_eq!(
            unsigned(&[0x01, 0, 0, 0x02]),
            Value::Unsigned32(0x0100_0002)
        );
        assert_eq!(
            unsigned(&[0x01, 0, 0, 0, 0x02]),
            Value::Unsigned64(0x01_0000_0002)
        );
        assert_eq!(unsigned(&[0xff; 7]), Value::Unsigned64(0xff_ffff_ffff_ffff));
        assert_eq!(unsigned(&[0xff; 8]), Value::Unsigned64(u64::MAX));
    }

    #[test]
    fn integers_are_read_at_the_field_length_whatever_their_width() {
        assert_eq!(
            decode(DataType::Unsigned8, &[0, 0, 1, 0]),
            Value::Unsigned32(256)
        );
        assert_eq!(decode(DataType::Unsigned64, &[7]), Value::Unsigned8(7));
        assert_eq!(
            decode(DataType::Signed8, &[0xff, 0xfe]),
            Value::Signed16(-2)
        );
        assert_eq!(
            decode(DataType::Float64, &[0x3f, 0x80, 0, 0]),
            Value::Float32(1.0)
        );
    }

    #[test]
    fn unsigned256_takes_9_to_32_bytes_with_leading_zeros_dropped() {
        let mut bytes = [0; 32];
        bytes[0] = 0xab;
        bytes[31] = 1;
        assert_eq!(
            decode(DataType::Unsigned256, &bytes),
            Value::Unsigned256(Box::new(bytes))
        );
        for length in [9, 16, 31] {
            let mut padded = [0; 32];
            padded[32 - length] = 0xab;
            padded[31] = 1;
            assert_eq!(
                decode(DataType::Unsigned256, &padded[32 - length..]),
                Value::Unsigned256(Box::new(padded)),
                "{length} bytes"
            );
        }
        assert_eq!(decode(DataType::Unsigned256, &[1]), Value::Unsigned8(1));
    }

    #[test]
    fn signed_integers_of_every_size_are_sign_extended() {
        let signed = |bytes: &[u8]| decode(DataType::Signed64, bytes);
        assert_eq!(signed(&[0xff]), Value::Signed8(-1));
        assert_eq!(signed(&[0xff, 0xfe]), Value::Signed16(-2));
        assert_eq!(signed(&[0xff, 0xff, 0xfd]), Value::Signed32(-3));
        assert_eq!(signed(&[0x7f, 0xff, 0xff]), Value::Signed32(0x7f_ffff));
        assert_eq!(signed(&[0xff, 0xff, 0xff, 0xfc]), Value::Signed32(-4));
        assert_eq!(signed(&[0xff; 5]), Value::Signed64(-1));
        assert_eq!(signed(&[0x80, 0, 0, 0, 0, 0]), Value::Signed64(-(1 << 47)));
        assert_eq!(
            signed(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Value::Signed64(0xffff_ffff_ffff)
        );
        assert_eq!(signed(&[0xff; 8]), Value::Signed64(-1));
    }

    #[test]
    fn floats() {
        assert_eq!(
            decode(DataType::Float32, &[0x3f, 0x80, 0, 0]),
            Value::Float32(1.0)
        );
        assert_eq!(
            decode(DataType::Float64, &[0xc0, 0x04, 0, 0, 0, 0, 0, 0]),
            Value::Float64(-2.5)
        );
    }

    #[test]
    fn booleans_other_than_one_or_two_are_null() {
        assert_eq!(decode(DataType::Boolean, &[1]), Value::Boolean(true));
        assert_eq!(decode(DataType::Boolean, &[2]), Value::Boolean(false));
        assert_eq!(decode(DataType::Boolean, &[0]), Value::Null);
        assert_eq!(decode(DataType::Boolean, &[3]), Value::Null);
    }

    #[test]
    fn strings_drop_trailing_nuls_and_ill_formed_utf8_is_null() {
        assert_eq!(
            decode(DataType::String, b"eth0\0\0"),
            Value::String("eth0".to_owned())
        );
        assert_eq!(decode(DataType::String, b""), Value::String(String::new()));
        assert_eq!(decode(DataType::String, &[0xff, 0xfe]), Value::Null);
    }

    #[test]
    fn addresses() {
        let mac = [0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e];
        assert_eq!(decode(DataType::MacAddress, &mac), Value::MacAddress(mac));
        assert_eq!(
            decode(DataType::Ipv4Address, &[192, 0, 2, 1]),
            Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            decode(DataType::Ipv6Address, &Ipv6Addr::LOCALHOST.octets()),
            Value::Ipv6Address(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn timestamps_keep_their_wire_encoding() {
        let ntp = [0xe9, 0x0e, 0x5b, 0x00, 0x80, 0, 0, 0x01];
        let ntp_timestamp = NtpTimestamp {
            seconds: 0xe90e_5b00,
            fraction: 0x8000_0001,
        };
        assert_eq!(
            decode(DataType::DateTimeSeconds, &1_700_000_000u32.to_be_bytes()),
            Value::DateTimeSeconds(1_700_000_000)
        );
        assert_eq!(
            decode(
                DataType::DateTimeMilliseconds,
                &1_700_000_000_000u64.to_be_bytes()
            ),
            Value::DateTimeMilliseconds(1_700_000_000_000)
        );
        assert_eq!(
            decode(DataType::DateTimeMicroseconds, &ntp),
            Value::DateTimeMicroseconds(ntp_timestamp)
        );
        assert_eq!(
            decode(DataType::DateTimeNanoseconds, &ntp),
            Value::DateTimeNanoseconds(ntp_timestamp)
        );
    }

    #[test]
    fn a_length_with_no_encoding_keeps_the_bytes() {
        for (data_type, bytes) in [
            (DataType::Unsigned64, &[0u8; 33][..]),
            (DataType::Unsigned32, &[]),
            (DataType::Unsigned256, &[0; 33]),
            (DataType::Signed64, &[0; 16]),
            (DataType::Float64, &[0; 2]),
            (DataType::Boolean, &[1, 1]),
            (DataType::MacAddress, &[0; 4]),
            (DataType::DateTimeMilliseconds, &[0; 4]),
            (DataType::Ipv4Address, &[0; 16]),
            (DataType::Ipv6Address, &[0; 4]),
            (DataType::OctetArray, &[1, 2, 3]),
            (DataType::BasicList, &[1, 2, 3]),
            (DataType::SubTemplateList, &[1, 2, 3]),
            (DataType::SubTemplateMultiList, &[1, 2, 3]),
        ] {
            assert_eq!(
                decode(data_type, bytes),
                Value::OctetArray(bytes.to_vec()),
                "{data_type:?} of {} bytes",
                bytes.len()
            );
        }
    }
}
