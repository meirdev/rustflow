use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{map, map_opt, verify};
use nom::number::complete::{be_u16, be_u32, be_u64};
use nom::{IResult, Parser};

/// Difference between NTP epoch (1900-01-01) and UNIX epoch (1970-01-01) in
/// seconds
const NTP_UNIX_EPOCH_DIFF: u64 = 2_208_988_800;

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

pub fn string(length: usize) -> impl Fn(&[u8]) -> IResult<&[u8], String> {
    move |input: &[u8]| {
        map_opt(take(length), |v: &[u8]| {
            from_utf8(v).ok().map(|v| v.to_string())
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
