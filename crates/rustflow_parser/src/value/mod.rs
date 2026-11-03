//! Field values, decoded the same way for NetFlow v9 and IPFIX: a template
//! gives each field a length and a type, and the type's data type says how
//! to read the field's bytes (RFC 7011 section 6.1).
use std::net::{Ipv4Addr, Ipv6Addr};

pub use decode::decode;

use crate::ipfix::{BasicList, SubTemplateList, SubTemplateMultiList};

mod decode;
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

/// A timestamp in NTP format (RFC 5905 section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NtpTimestamp {
    /// Seconds since 1900-01-01 UTC, modulo 2^32.
    pub seconds: u32,
    /// The fraction of a second, in units of 2^-32 seconds.
    pub fraction: u32,
}
