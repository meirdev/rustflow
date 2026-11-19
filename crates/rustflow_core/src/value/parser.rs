use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use winnow::Parser;
use winnow::error::ContextError;
use winnow::token::take;

use super::{MacAddress, NtpTimestamp, Value};
use crate::information_element::DataType;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    InvalidLength { data_type: DataType, len: usize },
    InvalidBoolean(u8),
    InvalidUtf8(std::str::Utf8Error),
    Unsupported(DataType),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { data_type, len } => {
                write!(f, "invalid length {len} for {data_type}")
            }
            Self::InvalidBoolean(b) => write!(f, "invalid boolean value {b}"),
            Self::InvalidUtf8(_) => f.write_str("invalid UTF-8 string"),
            Self::Unsupported(data_type) => write!(f, "unsupported data type {data_type}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(e) => Some(e),
            _ => None,
        }
    }
}

impl DataType {
    pub fn decode(&self, data: &[u8]) -> Result<Value, DecodeError> {
        let data_type = *self;
        let invalid_len = || DecodeError::InvalidLength {
            data_type,
            len: data.len(),
        };

        let value = match data_type {
            Self::OctetArray => Value::OctetArray(data.to_vec()),
            Self::String => Value::String(
                std::str::from_utf8(data)
                    .map_err(DecodeError::InvalidUtf8)?
                    .to_owned(),
            ),

            Self::Unsigned8 => {
                Value::Unsigned8(read_unsigned(data, 1).ok_or_else(invalid_len)? as u8)
            }
            Self::Unsigned16 => {
                Value::Unsigned16(read_unsigned(data, 2).ok_or_else(invalid_len)? as u16)
            }
            Self::Unsigned32 => {
                Value::Unsigned32(read_unsigned(data, 4).ok_or_else(invalid_len)? as u32)
            }
            Self::Unsigned64 => Value::Unsigned64(read_unsigned(data, 8).ok_or_else(invalid_len)?),
            Self::Unsigned256 => {
                if data.is_empty() || data.len() > 32 {
                    return Err(invalid_len());
                }
                let mut buf = [0u8; 32];
                buf[32 - data.len()..].copy_from_slice(data);
                Value::Unsigned256(Box::new(buf))
            }

            Self::Signed8 => Value::Signed8(read_signed(data, 1).ok_or_else(invalid_len)? as i8),
            Self::Signed16 => Value::Signed16(read_signed(data, 2).ok_or_else(invalid_len)? as i16),
            Self::Signed32 => Value::Signed32(read_signed(data, 4).ok_or_else(invalid_len)? as i32),
            Self::Signed64 => Value::Signed64(read_signed(data, 8).ok_or_else(invalid_len)?),

            Self::Float32 => {
                Value::Float32(f32::from_be_bytes(fixed(data).ok_or_else(invalid_len)?))
            }
            Self::Float64 => match data.len() {
                8 => Value::Float64(f64::from_be_bytes(fixed(data).ok_or_else(invalid_len)?)),
                4 => {
                    Value::Float64(f32::from_be_bytes(fixed(data).ok_or_else(invalid_len)?).into())
                }
                _ => return Err(invalid_len()),
            },

            Self::Boolean => match data {
                [1] => Value::Boolean(true),
                [2] => Value::Boolean(false),
                [b] => return Err(DecodeError::InvalidBoolean(*b)),
                _ => return Err(invalid_len()),
            },

            Self::MacAddress => {
                Value::MacAddress(MacAddress::from(fixed(data).ok_or_else(invalid_len)?))
            }
            Self::Ipv4Address => {
                Value::Ipv4Address(Ipv4Addr::from(fixed::<4>(data).ok_or_else(invalid_len)?))
            }
            Self::Ipv6Address => {
                Value::Ipv6Address(Ipv6Addr::from(fixed::<16>(data).ok_or_else(invalid_len)?))
            }

            Self::DateTimeSeconds => {
                Value::DateTimeSeconds(u32::from_be_bytes(fixed(data).ok_or_else(invalid_len)?))
            }
            Self::DateTimeMilliseconds => Value::DateTimeMilliseconds(u64::from_be_bytes(
                fixed(data).ok_or_else(invalid_len)?,
            )),
            Self::DateTimeMicroseconds => {
                Value::DateTimeMicroseconds(read_ntp(data).ok_or_else(invalid_len)?)
            }
            Self::DateTimeNanoseconds => {
                Value::DateTimeNanoseconds(read_ntp(data).ok_or_else(invalid_len)?)
            }

            Self::BasicList | Self::SubTemplateList | Self::SubTemplateMultiList => {
                return Err(DecodeError::Unsupported(data_type));
            }
        };

        Ok(value)
    }

    pub fn decode_or_octets(&self, data: &[u8]) -> Value {
        self.decode(data)
            .unwrap_or_else(|_| Value::OctetArray(data.to_vec()))
    }
}

pub fn parse_value<'i>(
    data_type: DataType,
    length: usize,
) -> impl Parser<&'i [u8], Value, ContextError> {
    take(length).map(move |bytes| data_type.decode_or_octets(bytes))
}

fn fixed<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.try_into().ok()
}

fn read_unsigned(data: &[u8], max: usize) -> Option<u64> {
    if data.is_empty() || data.len() > max || data.len() > 8 {
        return None;
    }
    let mut bytes = [0u8; 8];
    bytes[8 - data.len()..].copy_from_slice(data);
    Some(u64::from_be_bytes(bytes))
}

fn read_signed(data: &[u8], max: usize) -> Option<i64> {
    if data.is_empty() || data.len() > max || data.len() > 8 {
        return None;
    }
    // Extend the most significant bit through the leading bytes.
    let extension = if data[0] & 0x80 != 0 { 0xff } else { 0x00 };
    let mut bytes = [extension; 8];
    bytes[8 - data.len()..].copy_from_slice(data);
    Some(i64::from_be_bytes(bytes))
}

fn read_ntp(data: &[u8]) -> Option<NtpTimestamp> {
    let bytes: [u8; 8] = fixed(data)?;
    Some(NtpTimestamp {
        seconds: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        fraction: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_or_octets_keeps_bad_values_as_octets() {
        assert_eq!(
            DataType::Unsigned16.decode_or_octets(&[1, 2]),
            Value::Unsigned16(0x0102)
        );
        // A boolean is 1 or 2.
        assert_eq!(
            DataType::Boolean.decode_or_octets(&[7]),
            Value::OctetArray(vec![7])
        );
        // Too long for an unsigned16.
        assert_eq!(
            DataType::Unsigned16.decode_or_octets(&[1, 2, 3]),
            Value::OctetArray(vec![1, 2, 3])
        );
    }

    #[test]
    fn parse_value_takes_exactly_the_field() {
        let mut input = &[0, 53, 0xaa][..];
        assert_eq!(
            parse_value(DataType::Unsigned16, 2).parse_next(&mut input),
            Ok(Value::Unsigned16(53))
        );
        assert_eq!(input, [0xaa]);

        // A value that does not decode still consumes its field.
        let mut input = &[7, 0xaa][..];
        assert_eq!(
            parse_value(DataType::Boolean, 1).parse_next(&mut input),
            Ok(Value::OctetArray(vec![7]))
        );
        assert_eq!(input, [0xaa]);

        // Fewer octets than the field's length.
        assert!(
            parse_value(DataType::Unsigned32, 4)
                .parse_next(&mut &[0, 1][..])
                .is_err()
        );
    }

    #[test]
    fn unsigned_values() {
        let cases: &[(&[u8], usize, Option<u64>)] = &[
            (&[0x00], 1, Some(0)),
            (&[0xff], 1, Some(255)),
            (&[0x01, 0x00], 2, Some(256)),
            (&[0x12, 0x34, 0x56], 4, Some(0x12_34_56)),
            (&[0x00, 0x01], 2, Some(1)),
            (&[0xff; 4], 4, Some(u32::MAX as u64)),
            (&[0xff; 8], 8, Some(u64::MAX)),
            (&[0x80, 0, 0, 0, 0, 0, 0, 0], 8, Some(1u64 << 63)),
        ];

        for &(data, max, expected) in cases {
            assert_eq!(
                read_unsigned(data, max),
                expected,
                "data={data:02x?}, max={max}",
            );
        }
    }

    #[test]
    fn signed_values() {
        let cases: &[(&[u8], usize, Option<i64>)] = &[
            (&[0x00], 1, Some(0)),
            (&[0x7f], 1, Some(127)),
            (&[0x80], 1, Some(-128)),
            (&[0xff], 1, Some(-1)),
            (&[0x00, 0x80], 2, Some(128)),
            (&[0xff, 0xfe], 2, Some(-2)),
            (&[0x80, 0x00], 2, Some(-32768)),
            (&[0x7f, 0xff, 0xff], 4, Some(8_388_607)),
            (&[0x80, 0x00, 0x00], 4, Some(-8_388_608)),
            (&[0xff; 8], 8, Some(-1)),
            (
                &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                8,
                Some(i64::MAX),
            ),
            (&[0x80, 0, 0, 0, 0, 0, 0, 0], 8, Some(i64::MIN)),
        ];

        for &(data, max, expected) in cases {
            assert_eq!(
                read_signed(data, max),
                expected,
                "data={data:02x?}, max={max}",
            );
        }
    }

    #[test]
    fn invalid_lengths() {
        let cases: &[(&[u8], usize)] = &[
            (&[], 8),           // Empty input.
            (&[0x01], 0),       // No bytes allowed.
            (&[0x01, 0x02], 1), // Exceeds the field's maximum.
            (&[0; 9], 8),       // Exceeds both limits.
            (&[0; 9], 16),      // Exceeds u64/i64 despite a larger max.
        ];

        for &(data, max) in cases {
            assert_eq!(read_unsigned(data, max), None);
            assert_eq!(read_signed(data, max), None);
        }
    }

    #[test]
    fn every_supported_width() {
        for len in 1..=8 {
            let zeros = vec![0x00; len];
            let ones = vec![0xff; len];

            let unsigned_max = u64::MAX >> (8 * (8 - len));

            assert_eq!(read_unsigned(&zeros, 8), Some(0));
            assert_eq!(read_unsigned(&ones, 8), Some(unsigned_max));
            assert_eq!(read_signed(&zeros, 8), Some(0));
            assert_eq!(read_signed(&ones, 8), Some(-1));
        }
    }
}
