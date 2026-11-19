mod display;
mod encoder;
mod list;
mod parser;
#[cfg(feature = "serde")]
mod serialize;

use std::net::{Ipv4Addr, Ipv6Addr};

use jiff::Timestamp;

pub use self::display::TextError;
pub use self::encoder::{EncodeError, check_value, encode_value, natural_length};
pub use self::list::{BasicList, ListRecords, SubTemplateList, SubTemplateMultiList};
pub use self::parser::{DecodeError, parse_value};
#[cfg(feature = "serde")]
pub(crate) use self::serialize::{field_keys, serialize_data_set};
pub use crate::mac_address::MacAddress;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MILLIS_PER_SECOND: u64 = 1_000;

/// Seconds between 1900-01-01 and 1970-01-01.
const NTP_UNIX_EPOCH_OFFSET: i64 = 2_208_988_800;

/// Both NTP and dateTimeSeconds use a 32-bit seconds counter, which wraps
/// every 2^32 seconds (an "era").
const ERA_SECONDS: i64 = 1 << 32;

/// Converts a wrapping 32-bit `seconds` counter that starts at `epoch` (Unix
/// seconds) to the era closest to `reference`.
///
/// RFC 7011 §5.2: the era is implicit, and the collector determines it from
/// context such as the message's Export Time.
fn nearest_era(seconds: u32, epoch: i64, nanos: i32, reference: Timestamp) -> Timestamp {
    let offset = reference.as_second() - epoch - i64::from(seconds);
    let era = (offset + ERA_SECONDS / 2).div_euclid(ERA_SECONDS);

    // Near the edges of jiff's range the nearest era can fall outside it;
    // the neighbouring era on the other side of `reference` is then valid.
    in_era(seconds, epoch, nanos, era)
        .or_else(|| in_era(seconds, epoch, nanos, era - 1))
        .or_else(|| in_era(seconds, epoch, nanos, era + 1))
        .expect("an era adjacent to an in-range reference is in range")
}

fn in_era(seconds: u32, epoch: i64, nanos: i32, era: i64) -> Option<Timestamp> {
    Timestamp::new(epoch + era * ERA_SECONDS + i64::from(seconds), nanos).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    pub fn to_timestamp(self) -> Timestamp {
        // Using the RFC 4330 pivot: top bit of `seconds` set means era 0 (1968..2036),
        // clear means era 1 (2036..2104).
        let era = if self.seconds & 0x8000_0000 != 0 {
            0
        } else {
            1
        };
        self.in_era(era)
            .expect("NTP eras 0 and 1 are within Timestamp range")
    }

    pub fn to_timestamp_relative_to(self, reference: Timestamp) -> Timestamp {
        nearest_era(
            self.seconds,
            -NTP_UNIX_EPOCH_OFFSET,
            self.nanos(),
            reference,
        )
    }

    fn in_era(self, era: i64) -> Option<Timestamp> {
        in_era(self.seconds, -NTP_UNIX_EPOCH_OFFSET, self.nanos(), era)
    }

    fn nanos(self) -> i32 {
        ((u64::from(self.fraction) * NANOS_PER_SECOND) >> 32) as i32
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    // Boxed to keep `Value` at 32 bytes instead of 40; unsigned256 is rare.
    Unsigned256(Box<[u8; 32]>),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress(MacAddress),
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(u32),
    DateTimeMilliseconds(u64),
    DateTimeMicroseconds(NtpTimestamp),
    DateTimeNanoseconds(NtpTimestamp),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(Box<BasicList>),
    SubTemplateList(Box<SubTemplateList>),
    SubTemplateMultiList(Box<SubTemplateMultiList>),
    Null,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Unsigned8(v) => Some(v.into()),
            Self::Unsigned16(v) => Some(v.into()),
            Self::Unsigned32(v) => Some(v.into()),
            Self::Unsigned64(v) => Some(v),
            _ => None,
        }
    }

    pub fn to_timestamp(&self) -> Option<Timestamp> {
        self.to_timestamp_with(None)
    }

    pub fn to_timestamp_relative_to(&self, reference: Timestamp) -> Option<Timestamp> {
        self.to_timestamp_with(Some(reference))
    }

    fn to_timestamp_with(&self, reference: Option<Timestamp>) -> Option<Timestamp> {
        match *self {
            Self::DateTimeSeconds(seconds) => Some(match reference {
                Some(reference) => nearest_era(seconds, 0, 0, reference),
                None => in_era(seconds, 0, 0, 0).expect("era 0 is within Timestamp range"),
            }),
            Self::DateTimeMilliseconds(millis) => {
                // Divide before converting, avoiding a lossy u64 -> i64 cast.
                let seconds = (millis / MILLIS_PER_SECOND) as i64;
                let nanos = ((millis % MILLIS_PER_SECOND) * 1_000_000) as i32;

                Timestamp::new(seconds, nanos).ok()
            }
            Self::DateTimeMicroseconds(ntp) | Self::DateTimeNanoseconds(ntp) => {
                Some(match reference {
                    Some(reference) => ntp.to_timestamp_relative_to(reference),
                    None => ntp.to_timestamp(),
                })
            }
            _ => None,
        }
    }
}
