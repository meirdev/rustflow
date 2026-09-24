use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{map, map_opt, verify};
use nom::number::complete::{be_u8, be_u16, be_u32, be_u64};
use nom::{IResult, Parser};

/// Difference between NTP epoch (1900-01-01) and UNIX epoch (1970-01-01) in
/// seconds
pub const NTP_UNIX_EPOCH_DIFF: u64 = 2_208_988_800;

pub fn ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

pub fn ipv6_addr(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    map(take(16usize), |v| {
        Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap())
    })
    .parse(input)
}

fn ntp_to_datetime(ntp_secs: u32, fraction: u32) -> Option<DateTime<Utc>> {
    let unix_secs = (ntp_secs as i64).checked_sub(NTP_UNIX_EPOCH_DIFF as i64)?;
    let nanos = ((fraction as u64) * 1_000_000_000) >> 32;
    DateTime::<Utc>::from_timestamp(unix_secs, nanos as u32)
}

pub fn timestamp_secs(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |v| DateTime::<Utc>::from_timestamp_secs(v as i64)).parse(input)
}

pub fn timestamp_millis(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u64, |v| DateTime::<Utc>::from_timestamp_millis(v as i64)).parse(input)
}

pub fn timestamp_micros(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt((be_u32, be_u32), |(s, f)| ntp_to_datetime(s, f)).parse(input)
}

pub fn timestamp_nanos(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt((be_u32, be_u32), |(s, f)| ntp_to_datetime(s, f)).parse(input)
}

pub fn macaddr6(input: &[u8]) -> IResult<&[u8], MacAddr6> {
    map(take(6usize), |v| {
        MacAddr6::from(<[u8; 6]>::try_from(v).unwrap())
    })
    .parse(input)
}

/// A UTF-8 string, or `None` for ill-formed UTF-8, which a collector
/// ignores (RFC 7011 section 6.1.6). Exporters pad a fixed-length string
/// element with trailing NULs, which are not part of the value.
pub fn string(length: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Option<String>> {
    move |input: &[u8]| {
        map(take(length), |v: &[u8]| {
            from_utf8(v)
                .ok()
                .map(|v| v.trim_end_matches('\0').to_string())
        })
        .parse(input)
    }
}

/// RFC 7011 section 6.1.3: 1 is true and 2 is false; anything else is
/// ignored.
pub fn boolean(input: &[u8]) -> IResult<&[u8], Option<bool>> {
    map(be_u8, |v| match v {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    })
    .parse(input)
}

/// Big-endian unsigned integer of a reduced size (RFC 7011 section 6.2), for
/// the 5-7 byte widths nom has no built-in parser for.
pub fn be_uint(length: usize) -> impl Fn(&[u8]) -> IResult<&[u8], u64> {
    move |input| {
        map(take(length), |bytes: &[u8]| {
            bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
        })
        .parse(input)
    }
}

/// Big-endian two's-complement signed integer of a reduced size (RFC 7011
/// section 6.2): the most significant bit of the encoded value is the sign bit.
pub fn be_int(length: usize) -> impl Fn(&[u8]) -> IResult<&[u8], i64> {
    move |input| {
        map(be_uint(length), |v| {
            let shift = 64 - length * 8;
            ((v << shift) as i64) >> shift
        })
        .parse(input)
    }
}

pub fn vector(length: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<u8>> {
    move |input: &[u8]| map(take(length), |v: &[u8]| v.to_vec()).parse(input)
}

pub fn verify_version(input: &[u8], expected_version: u16) -> IResult<&[u8], u16> {
    verify(be_u16, |v| *v == expected_version).parse(input)
}
