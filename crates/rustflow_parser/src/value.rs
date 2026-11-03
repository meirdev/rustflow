//! Field values, decoded the same way for NetFlow v9 and IPFIX: a template
//! gives each field a length and a type, and the type's data type says how
//! to read the field's bytes (RFC 7011 section 6.1).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use crate::ipfix::{BasicList, SubTemplateList, SubTemplateMultiList};

/// An abstract data type, numbered as in IANA's IPFIX Information Element
/// Data Types registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// A decoded field value. Timestamps keep their wire encoding.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Value {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    /// Big-endian.
    Unsigned256(Box<[u8; 32]>),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress([u8; 6]),
    OctetArray(Vec<u8>),
    String(String),
    /// Seconds since 1970-01-01 UTC.
    DateTimeSeconds(u32),
    /// Milliseconds since 1970-01-01 UTC.
    DateTimeMilliseconds(u64),
    /// With microsecond precision.
    DateTimeMicroseconds(NtpTimestamp),
    /// With nanosecond precision.
    DateTimeNanoseconds(NtpTimestamp),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(Box<BasicList>),
    SubTemplateList(Box<SubTemplateList>),
    SubTemplateMultiList(Box<SubTemplateMultiList>),
    /// A value to ignore: a string that is not UTF-8, or a boolean other
    /// than 1 (true) or 2 (false).
    Null,
}

/// A timestamp in NTP format (RFC 5905 section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NtpTimestamp {
    /// Seconds since 1900-01-01 UTC, modulo 2^32.
    pub seconds: u32,
    /// The fraction of a second, in units of 2^-32 seconds.
    pub fraction: u32,
}

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

#[cfg(feature = "jiff")]
mod timestamp {
    use jiff::Timestamp;

    use super::{NtpTimestamp, Value};

    /// Seconds from 1900-01-01, the NTP epoch, to 1970-01-01.
    const NTP_UNIX_EPOCH_DIFF: i64 = 2_208_988_800;

    /// The bottom 11 bits of a microsecond fraction must be ignored (RFC
    /// 7011 section 6.1.9).
    const MICROSECOND_FRACTION_MASK: u32 = !0x7ff;

    impl Value {
        /// The instant a date-time value stands for, or `None` for another
        /// value or an instant jiff cannot represent.
        ///
        /// Seconds and NTP timestamps wrap every 2^32 seconds, so
        /// `reference`, a time near the value such as the packet's export
        /// time, picks the era that puts the value nearest it (RFC 7011
        /// section 5.2). Fractions are rounded to the value's precision.
        pub fn timestamp(&self, reference: Timestamp) -> Option<Timestamp> {
            match *self {
                Value::DateTimeSeconds(seconds) => {
                    Timestamp::from_second(nearest_era(seconds, 0, reference)).ok()
                }
                Value::DateTimeMilliseconds(millis) => {
                    Timestamp::from_millisecond(i64::try_from(millis).ok()?).ok()
                }
                Value::DateTimeMicroseconds(ntp) => {
                    ntp.timestamp(reference, MICROSECOND_FRACTION_MASK, 1_000)
                }
                Value::DateTimeNanoseconds(ntp) => ntp.timestamp(reference, u32::MAX, 1),
                _ => None,
            }
        }
    }

    impl NtpTimestamp {
        /// `precision` is in nanoseconds.
        fn timestamp(
            self,
            reference: Timestamp,
            fraction_mask: u32,
            precision: u64,
        ) -> Option<Timestamp> {
            let seconds = nearest_era(self.seconds, -NTP_UNIX_EPOCH_DIFF, reference);
            let per_second = 1_000_000_000 / precision;
            let units = (u64::from(self.fraction & fraction_mask) * per_second + (1 << 31)) >> 32;
            let nanos = i128::from(seconds) * 1_000_000_000 + i128::from(units * precision);
            Timestamp::from_nanosecond(nanos).ok()
        }
    }

    /// The UNIX second `seconds` after `epoch`, moved by whole 2^32-second
    /// eras to lie nearest `reference`.
    fn nearest_era(seconds: u32, epoch: i64, reference: Timestamp) -> i64 {
        const ERA: i64 = 1 << 32;
        let second = epoch + i64::from(seconds);
        let eras = (reference.as_second() - second + ERA / 2).div_euclid(ERA);
        second + eras * ERA
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NOW: i64 = 1_700_000_000;

        /// 2^32 seconds after the NTP epoch: 2036-02-07T06:28:16Z.
        const NTP_ERA_1: i64 = (1 << 32) - NTP_UNIX_EPOCH_DIFF;

        fn at(second: i64, nanosecond: i32) -> Timestamp {
            Timestamp::new(second, nanosecond).unwrap()
        }

        /// An NTP timestamp of the first era.
        fn ntp(unix_second: i64, fraction: u32) -> NtpTimestamp {
            NtpTimestamp {
                seconds: u32::try_from(unix_second + NTP_UNIX_EPOCH_DIFF).unwrap(),
                fraction,
            }
        }

        #[test]
        fn seconds_and_milliseconds_count_from_1970() {
            assert_eq!(
                Value::DateTimeSeconds(1_700_000_000).timestamp(at(NOW, 0)),
                Some(at(1_700_000_000, 0))
            );
            assert_eq!(
                Value::DateTimeMilliseconds(1_700_000_000_123).timestamp(at(NOW, 0)),
                Some(at(1_700_000_000, 123_000_000))
            );
        }

        #[test]
        fn seconds_wrap_into_the_era_nearest_the_reference() {
            let after_2106 = Value::DateTimeSeconds(100);
            assert_eq!(
                after_2106.timestamp(at((1 << 32) - 1_000, 0)),
                Some(at((1 << 32) + 100, 0))
            );
            assert_eq!(after_2106.timestamp(at(NOW, 0)), Some(at(100, 0)));
        }

        #[test]
        fn milliseconds_jiff_cannot_represent_are_none() {
            assert_eq!(
                Value::DateTimeMilliseconds(1 << 62).timestamp(at(NOW, 0)),
                None
            );
            assert_eq!(
                Value::DateTimeMilliseconds(u64::MAX).timestamp(at(NOW, 0)),
                None
            );
        }

        #[test]
        fn ntp_seconds_count_from_1900() {
            let epoch = NtpTimestamp {
                seconds: 0,
                fraction: 0,
            };
            assert_eq!(
                Value::DateTimeNanoseconds(epoch).timestamp(at(-NTP_UNIX_EPOCH_DIFF, 0)),
                Some(at(-NTP_UNIX_EPOCH_DIFF, 0))
            );
            assert_eq!(
                Value::DateTimeNanoseconds(ntp(NOW, 1 << 31)).timestamp(at(NOW, 0)),
                Some(at(NOW, 500_000_000))
            );
        }

        #[test]
        fn ntp_seconds_wrap_into_the_era_nearest_the_reference() {
            let after_2036 = Value::DateTimeNanoseconds(NtpTimestamp {
                seconds: 100,
                fraction: 0,
            });
            assert_eq!(
                after_2036.timestamp(at(NTP_ERA_1 - 1_000, 0)),
                Some(at(NTP_ERA_1 + 100, 0))
            );
            let in_1950 = at(-631_152_000, 0);
            assert_eq!(
                after_2036.timestamp(in_1950),
                Some(at(100 - NTP_UNIX_EPOCH_DIFF, 0))
            );
        }

        #[test]
        fn microseconds_ignore_the_bottom_11_fraction_bits() {
            let fraction = (1 << 31) | 0x7ff;
            assert_eq!(
                Value::DateTimeMicroseconds(ntp(NOW, fraction)).timestamp(at(NOW, 0)),
                Some(at(NOW, 500_000_000))
            );
            assert_eq!(
                Value::DateTimeNanoseconds(ntp(NOW, fraction)).timestamp(at(NOW, 0)),
                Some(at(NOW, 500_000_477))
            );
        }

        #[test]
        fn microseconds_round_to_the_microsecond_the_exporter_encoded() {
            let encoded = u32::try_from((123_456u64 << 32) / 1_000_000).unwrap();
            assert_eq!(
                Value::DateTimeMicroseconds(ntp(NOW, encoded & MICROSECOND_FRACTION_MASK))
                    .timestamp(at(NOW, 0)),
                Some(at(NOW, 123_456_000))
            );
        }

        #[test]
        fn a_fraction_that_rounds_up_carries_into_the_next_second() {
            for value in [
                Value::DateTimeMicroseconds(ntp(NOW, u32::MAX)),
                Value::DateTimeNanoseconds(ntp(NOW, u32::MAX)),
            ] {
                assert_eq!(value.timestamp(at(NOW, 0)), Some(at(NOW + 1, 0)));
            }
        }

        #[test]
        fn other_values_have_no_timestamp() {
            assert_eq!(Value::Unsigned32(1_700_000_000).timestamp(at(NOW, 0)), None);
        }
    }
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
