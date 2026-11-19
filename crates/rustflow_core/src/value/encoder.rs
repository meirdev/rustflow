use std::fmt;

use bytes::BufMut;

use super::{NtpTimestamp, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    InvalidLength { length: u16 },
    Unsupported,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { length } => {
                write!(f, "the value cannot be written in {length} octets")
            }
            Self::Unsupported => f.write_str("the value has no fixed-length encoding"),
        }
    }
}

impl std::error::Error for EncodeError {}

pub fn encode_value(
    out: &mut impl BufMut,
    value: &Value,
    length: u16,
) -> Result<usize, EncodeError> {
    let octets = octets(value, length)?;
    out.put_slice(octets.as_slice());
    Ok(octets.as_slice().len())
}

pub fn check_value(value: &Value, length: u16) -> Result<(), EncodeError> {
    octets(value, length).map(drop)
}

/// The octets a value is written as: copied when short, borrowed when they
/// are already there.
enum Octets<'a> {
    Inline { buf: [u8; 32], len: usize },
    Borrowed(&'a [u8]),
}

impl Octets<'_> {
    fn inline(octets: &[u8]) -> Self {
        let mut buf = [0; 32];
        buf[..octets.len()].copy_from_slice(octets);
        Self::Inline {
            buf,
            len: octets.len(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { buf, len } => &buf[..*len],
            Self::Borrowed(octets) => octets,
        }
    }
}

fn octets(value: &Value, length: u16) -> Result<Octets<'_>, EncodeError> {
    let invalid = EncodeError::InvalidLength { length };
    let exactly = |size: usize| (usize::from(length) == size).then_some(()).ok_or(invalid);

    Ok(match value {
        Value::Unsigned8(v) => unsigned(u64::from(*v), 1, length)?,
        Value::Unsigned16(v) => unsigned(u64::from(*v), 2, length)?,
        Value::Unsigned32(v) => unsigned(u64::from(*v), 4, length)?,
        Value::Unsigned64(v) => unsigned(*v, 8, length)?,
        Value::Signed8(v) => signed(i64::from(*v), 1, length)?,
        Value::Signed16(v) => signed(i64::from(*v), 2, length)?,
        Value::Signed32(v) => signed(i64::from(*v), 4, length)?,
        Value::Signed64(v) => signed(*v, 8, length)?,
        Value::Unsigned256(v) => {
            let size = usize::from(length);
            if !(1..=32).contains(&size) || v[..32 - size].iter().any(|&b| b != 0) {
                return Err(invalid);
            }
            Octets::Borrowed(&v[32 - size..])
        }

        Value::Float32(v) => {
            exactly(4)?;
            Octets::inline(&v.to_be_bytes())
        }
        Value::Float64(v) => match length {
            8 => Octets::inline(&v.to_be_bytes()),
            4 if v.is_nan() || f64::from(*v as f32) == *v => {
                Octets::inline(&(*v as f32).to_be_bytes())
            }
            _ => return Err(invalid),
        },

        Value::Boolean(v) => {
            exactly(1)?;
            Octets::inline(&[if *v { 1 } else { 2 }])
        }
        Value::MacAddress(v) => {
            exactly(6)?;
            Octets::inline(&v.octets())
        }
        Value::Ipv4Address(v) => {
            exactly(4)?;
            Octets::inline(&v.octets())
        }
        Value::Ipv6Address(v) => {
            exactly(16)?;
            Octets::inline(&v.octets())
        }
        Value::OctetArray(v) => {
            exactly(v.len())?;
            Octets::Borrowed(v)
        }
        Value::String(v) => {
            exactly(v.len())?;
            Octets::Borrowed(v.as_bytes())
        }

        Value::DateTimeSeconds(v) => {
            exactly(4)?;
            Octets::inline(&v.to_be_bytes())
        }
        Value::DateTimeMilliseconds(v) => {
            exactly(8)?;
            Octets::inline(&v.to_be_bytes())
        }
        Value::DateTimeMicroseconds(v) | Value::DateTimeNanoseconds(v) => {
            exactly(8)?;
            let NtpTimestamp { seconds, fraction } = *v;
            Octets::inline(&((u64::from(seconds) << 32) | u64::from(fraction)).to_be_bytes())
        }

        Value::BasicList(_)
        | Value::SubTemplateList(_)
        | Value::SubTemplateMultiList(_)
        | Value::Null => return Err(EncodeError::Unsupported),
    })
}

pub fn natural_length(value: &Value) -> Option<usize> {
    Some(match value {
        Value::Unsigned8(_) | Value::Signed8(_) | Value::Boolean(_) => 1,
        Value::Unsigned16(_) | Value::Signed16(_) => 2,
        Value::Unsigned32(_)
        | Value::Signed32(_)
        | Value::Float32(_)
        | Value::Ipv4Address(_)
        | Value::DateTimeSeconds(_) => 4,
        Value::MacAddress(_) => 6,
        Value::Unsigned64(_)
        | Value::Signed64(_)
        | Value::Float64(_)
        | Value::DateTimeMilliseconds(_)
        | Value::DateTimeMicroseconds(_)
        | Value::DateTimeNanoseconds(_) => 8,
        Value::Ipv6Address(_) => 16,
        Value::Unsigned256(_) => 32,
        Value::OctetArray(v) => v.len(),
        Value::String(v) => v.len(),
        Value::BasicList(_)
        | Value::SubTemplateList(_)
        | Value::SubTemplateMultiList(_)
        | Value::Null => return None,
    })
}

fn unsigned(value: u64, size: usize, length: u16) -> Result<Octets<'static>, EncodeError> {
    let octets = usize::from(length);
    let fits = (1..=size).contains(&octets) && (octets == 8 || value >> (8 * octets) == 0);
    if !fits {
        return Err(EncodeError::InvalidLength { length });
    }
    Ok(Octets::inline(&value.to_be_bytes()[8 - octets..]))
}

fn signed(value: i64, size: usize, length: u16) -> Result<Octets<'static>, EncodeError> {
    let octets = usize::from(length);
    let shift = 64 - 8 * octets as u32;
    let fits = (1..=size).contains(&octets) && (value << shift) >> shift == value;
    if !fits {
        return Err(EncodeError::InvalidLength { length });
    }
    Ok(Octets::inline(&value.to_be_bytes()[8 - octets..]))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::information_element::DataType;
    use crate::value::MacAddress;

    fn encoded(value: &Value, length: u16) -> std::result::Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        let written = encode_value(&mut out, value, length)?;
        assert_eq!(written, out.len());
        Ok(out)
    }

    #[test]
    fn integers_in_their_size_or_fewer_octets() {
        assert_eq!(encoded(&Value::Unsigned16(0x0102), 2), Ok(vec![1, 2]));
        assert_eq!(encoded(&Value::Unsigned64(1500), 4), Ok(vec![0, 0, 5, 220]));
        assert_eq!(encoded(&Value::Unsigned64(u64::MAX), 8), Ok(vec![0xff; 8]));
        assert_eq!(encoded(&Value::Signed32(-2), 1), Ok(vec![0xfe]));
        assert_eq!(
            encoded(&Value::Signed64(i64::MIN), 8),
            Ok(i64::MIN.to_be_bytes().to_vec())
        );

        let invalid = |length| Err(EncodeError::InvalidLength { length });
        // Does not fit.
        assert_eq!(encoded(&Value::Unsigned64(0x1_0000), 2), invalid(2));
        assert_eq!(encoded(&Value::Signed16(200), 1), invalid(1));
        assert_eq!(encoded(&Value::Signed16(-129), 1), invalid(1));
        // Longer than the type, or empty.
        assert_eq!(encoded(&Value::Unsigned16(1), 4), invalid(4));
        assert_eq!(encoded(&Value::Unsigned8(0), 0), invalid(0));
    }

    #[test]
    fn floats_booleans_and_unsigned256() {
        assert_eq!(
            encoded(&Value::Float64(1.5), 4),
            Ok(1.5f32.to_be_bytes().to_vec())
        );
        assert_eq!(
            encoded(&Value::Float64(0.1), 4),
            Err(EncodeError::InvalidLength { length: 4 })
        );
        assert_eq!(encoded(&Value::Boolean(true), 1), Ok(vec![1]));
        assert_eq!(encoded(&Value::Boolean(false), 1), Ok(vec![2]));

        let mut wide = [0u8; 32];
        wide[31] = 7;
        assert_eq!(
            encoded(&Value::Unsigned256(Box::new(wide)), 2),
            Ok(vec![0, 7])
        );
        wide[0] = 1;
        assert!(encoded(&Value::Unsigned256(Box::new(wide)), 2).is_err());
    }

    #[test]
    fn errors_write_nothing_and_check_value_agrees() {
        let mut out = vec![0xff];
        assert!(encode_value(&mut out, &Value::Unsigned16(1), 4).is_err());
        assert_eq!(out, [0xff]);

        assert_eq!(check_value(&Value::Unsigned64(1500), 4), Ok(()));
        assert_eq!(
            check_value(&Value::Unsigned64(1 << 40), 4),
            Err(EncodeError::InvalidLength { length: 4 })
        );
        assert_eq!(check_value(&Value::Null, 0), Err(EncodeError::Unsupported));
    }

    #[test]
    fn fixed_size_values_need_their_exact_length() {
        assert_eq!(
            encoded(&Value::String("eth0".into()), 4),
            Ok(b"eth0".to_vec())
        );
        assert!(encoded(&Value::String("eth0".into()), 8).is_err());
        assert!(encoded(&Value::OctetArray(vec![1, 2]), 3).is_err());
        assert!(encoded(&Value::Ipv4Address(Ipv4Addr::LOCALHOST), 16).is_err());
        assert_eq!(encoded(&Value::Null, 4), Err(EncodeError::Unsupported));
    }

    #[test]
    fn decoding_reads_back_what_was_encoded() {
        let cases = [
            (DataType::Unsigned8, Value::Unsigned8(200), 1),
            (DataType::Unsigned64, Value::Unsigned64(1500), 4),
            (DataType::Signed32, Value::Signed32(-70_000), 4),
            (DataType::Signed64, Value::Signed64(-5), 2),
            (DataType::Float32, Value::Float32(2.5), 4),
            (DataType::Float64, Value::Float64(0.1), 8),
            (DataType::Boolean, Value::Boolean(false), 1),
            (
                DataType::MacAddress,
                Value::MacAddress(MacAddress::from([1, 2, 3, 4, 5, 6])),
                6,
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
            (DataType::String, Value::String("eth0".into()), 4),
            (DataType::OctetArray, Value::OctetArray(vec![9, 8, 7]), 3),
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
                DataType::DateTimeNanoseconds,
                Value::DateTimeNanoseconds(NtpTimestamp {
                    seconds: 1,
                    fraction: 2,
                }),
                8,
            ),
        ];
        for (data_type, value, length) in cases {
            let bytes = encoded(&value, length).unwrap();
            assert_eq!(data_type.decode(&bytes), Ok(value), "{data_type}");
        }
    }
}
