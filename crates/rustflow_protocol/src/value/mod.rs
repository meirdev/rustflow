//! Field values, decoded the same way for NetFlow v9 and IPFIX: a template
//! gives each field a length and a type, and the type's data type says how
//! to read the field's bytes (RFC 7011 section 6.1).

use std::net::{Ipv4Addr, Ipv6Addr};

pub use decode::decode;
pub use encode::{encode, natural_length};

use crate::ipfix::{BasicList, SubTemplateList, SubTemplateMultiList};

mod decode;
mod display;
mod encode;
#[cfg(feature = "jiff")]
mod timestamp;

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

impl Value {
    /// An unsigned integer of up to 64 bits, whatever its width.
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Unsigned8(v) => Some(v.into()),
            Self::Unsigned16(v) => Some(v.into()),
            Self::Unsigned32(v) => Some(v.into()),
            Self::Unsigned64(v) => Some(v),
            _ => None,
        }
    }
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

/// Seconds from 1900-01-01, the NTP epoch, to 1970-01-01.
const NTP_UNIX_EPOCH_DIFF: i64 = 2_208_988_800;

/// The bottom 11 bits of a microsecond fraction must be ignored (RFC 7011
/// section 6.1.9).
const MICROSECOND_FRACTION_MASK: u32 = !0x7ff;

impl NtpTimestamp {
    /// The fraction in nanoseconds, after `fraction_mask`, rounded to whole
    /// `precision` nanoseconds: a whole second if it rounds up to one.
    fn fraction_nanos(self, fraction_mask: u32, precision: u64) -> u64 {
        let per_second = 1_000_000_000 / precision;
        let units = (u64::from(self.fraction & fraction_mask) * per_second + (1 << 31)) >> 32;
        units * precision
    }
}
