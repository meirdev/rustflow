//! RFC 7373: the textual representation of values.

use std::fmt;

use super::{MICROSECOND_FRACTION_MASK, NTP_UNIX_EPOCH_DIFF, NtpTimestamp, Value};

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i128 = 86_400;

/// Writes a value in its RFC 7373 textual form.
///
/// A string is written as it is, for the enclosing format (CSV, JSON, ...)
/// to quote and escape (section 4.7). Lists have no textual form (section
/// 4.11), nor has `Null`: both are written as nothing.
///
/// RFC 7373 leaves out some cases, written here as follows:
/// - An unsigned256 value in the `0x` hexadecimal form section 4.2 allows for
///   unsigned integers.
/// - An NTP timestamp in its first era, 1900 to 2036, since a textual form has
///   no time to pick another by (RFC 7011 section 5.2).
/// - A year past 9999 with more than four digits.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Unsigned8(v) => write!(f, "{v}"),
            Value::Unsigned16(v) => write!(f, "{v}"),
            Value::Unsigned32(v) => write!(f, "{v}"),
            Value::Unsigned64(v) => write!(f, "{v}"),
            Value::Unsigned256(v) => unsigned256(f, v),
            Value::Signed8(v) => write!(f, "{v}"),
            Value::Signed16(v) => write!(f, "{v}"),
            Value::Signed32(v) => write!(f, "{v}"),
            Value::Signed64(v) => write!(f, "{v}"),
            Value::Float32(v) => float(f, *v),
            Value::Float64(v) => float(f, *v),
            Value::Boolean(v) => write!(f, "{v}"),
            Value::MacAddress(octets) => {
                write!(f, "{:02x}", octets[0])?;
                octets[1..]
                    .iter()
                    .try_for_each(|octet| write!(f, ":{octet:02x}"))
            }
            Value::OctetArray(bytes) => bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}")),
            Value::String(v) => f.write_str(v),
            Value::DateTimeSeconds(seconds) => {
                date_time(f, i128::from(*seconds) * NANOS_PER_SECOND, 0)
            }
            Value::DateTimeMilliseconds(millis) => date_time(f, i128::from(*millis) * 1_000_000, 3),
            Value::DateTimeMicroseconds(ntp) => date_time(
                f,
                first_era_nanos(*ntp, MICROSECOND_FRACTION_MASK, 1_000),
                6,
            ),
            Value::DateTimeNanoseconds(ntp) => date_time(f, first_era_nanos(*ntp, u32::MAX, 1), 9),
            Value::Ipv4Address(address) => write!(f, "{address}"),
            Value::Ipv6Address(address) => write!(f, "{address}"),
            Value::BasicList(_)
            | Value::SubTemplateList(_)
            | Value::SubTemplateMultiList(_)
            | Value::Null => Ok(()),
        }
    }
}

fn unsigned256(f: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    match bytes.iter().position(|&byte| byte != 0) {
        None => f.write_str("0x0"),
        Some(first) => {
            write!(f, "0x{:x}", bytes[first])?;
            bytes[first + 1..]
                .iter()
                .try_for_each(|byte| write!(f, "{byte:02x}"))
        }
    }
}

/// A decimal, in `e` notation or not, or `NaN`, `+inf` or `-inf` (RFC 7373
/// section 4.4). The RFC leaves the choice of notation to the writer: `e`
/// notation is used outside 1e-4 to 1e16, where a plain decimal would run to
/// hundreds of digits, and plain decimals within, where `e` notation would
/// turn 1.5 into `1.5e0`.
fn float<T>(f: &mut fmt::Formatter<'_>, value: T) -> fmt::Result
where
    T: fmt::Display + fmt::LowerExp + Into<f64> + Copy,
{
    let v: f64 = value.into();
    // Rust writes `NaN` and `-inf` as RFC 7373 does, but not `+inf`.
    if v == f64::INFINITY {
        f.write_str("+inf")
    } else if v == 0.0 || (1e-4..1e16).contains(&v.abs()) {
        write!(f, "{value}")
    } else {
        write!(f, "{value:e}")
    }
}

fn first_era_nanos(ntp: NtpTimestamp, fraction_mask: u32, precision: u64) -> i128 {
    let seconds = i128::from(ntp.seconds) - i128::from(NTP_UNIX_EPOCH_DIFF);
    seconds * NANOS_PER_SECOND + i128::from(ntp.fraction_nanos(fraction_mask, precision))
}

/// `YYYY-MM-DDTHH:MM:SS` in UTC, then `digits` digits of the second's
/// fraction (RFC 7373 section 4.8).
fn date_time(f: &mut fmt::Formatter<'_>, unix_nanos: i128, digits: u32) -> fmt::Result {
    let seconds = unix_nanos.div_euclid(NANOS_PER_SECOND);
    let (year, month, day) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    let time = seconds.rem_euclid(SECONDS_PER_DAY);
    write!(
        f,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        time / 3_600,
        time % 3_600 / 60,
        time % 60
    )?;
    if digits > 0 {
        let fraction = unix_nanos.rem_euclid(NANOS_PER_SECOND) / 10i128.pow(9 - digits);
        write!(f, ".{fraction:0width$}", width = digits as usize)?;
    }
    Ok(())
}

/// The proleptic Gregorian date `days` after 1970-01-01, by Howard Hinnant's
/// `civil_from_days`.
///
/// Not jiff's, which formats the same text: jiff is an optional feature, and
/// it stops at 9999-12-30T22:00:00 UTC, short of the dates a 64-bit
/// millisecond count reaches, which this writes with years past 9999.
fn civil_from_days(days: i128) -> (i128, i128, i128) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i128::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::protocol::ipfix::{BasicList, FieldSpecifier, ListSemantic};

    fn ntp(unix_second: i64, fraction: u32) -> NtpTimestamp {
        NtpTimestamp {
            seconds: u32::try_from(unix_second + NTP_UNIX_EPOCH_DIFF).unwrap(),
            fraction,
        }
    }

    #[test]
    fn integers_are_decimal() {
        assert_eq!(Value::Unsigned8(255).to_string(), "255");
        assert_eq!(
            Value::Unsigned64(u64::MAX).to_string(),
            "18446744073709551615"
        );
        assert_eq!(Value::Signed32(-42).to_string(), "-42");
        assert_eq!(
            Value::Signed64(i64::MIN).to_string(),
            "-9223372036854775808"
        );
    }

    #[test]
    fn unsigned256_is_hexadecimal_without_leading_zeros() {
        let mut bytes = [0; 32];
        assert_eq!(Value::Unsigned256(Box::new(bytes)).to_string(), "0x0");
        bytes[30] = 0x0a;
        bytes[31] = 0x0b;
        assert_eq!(Value::Unsigned256(Box::new(bytes)).to_string(), "0xa0b");
    }

    #[test]
    fn floats() {
        assert_eq!(Value::Float32(0.1).to_string(), "0.1");
        assert_eq!(Value::Float64(-2.5).to_string(), "-2.5");
        assert_eq!(Value::Float64(0.0).to_string(), "0");
        assert_eq!(Value::Float64(1e300).to_string(), "1e300");
        assert_eq!(Value::Float64(1.5e-10).to_string(), "1.5e-10");
        assert_eq!(Value::Float64(f64::NAN).to_string(), "NaN");
        assert_eq!(Value::Float32(f32::INFINITY).to_string(), "+inf");
        assert_eq!(Value::Float64(f64::NEG_INFINITY).to_string(), "-inf");
    }

    #[test]
    fn booleans_addresses_and_bytes() {
        assert_eq!(Value::Boolean(true).to_string(), "true");
        assert_eq!(Value::Boolean(false).to_string(), "false");
        assert_eq!(
            Value::MacAddress([0x00, 0x1b, 0x21, 0x3c, 0x4d, 0xfe]).to_string(),
            "00:1b:21:3c:4d:fe"
        );
        assert_eq!(
            Value::OctetArray(vec![0x0a, 0xff, 0x00]).to_string(),
            "0aff00"
        );
        assert_eq!(Value::OctetArray(Vec::new()).to_string(), "");
        assert_eq!(
            Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)).to_string(),
            "192.0.2.1"
        );
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(Value::Ipv6Address(address).to_string(), "2001:db8::1");
    }

    #[test]
    fn strings_are_left_for_the_enclosing_format_to_escape() {
        assert_eq!(
            Value::String("a \"b\",\nc".to_owned()).to_string(),
            "a \"b\",\nc"
        );
    }

    #[test]
    fn date_times_have_as_many_fraction_digits_as_their_precision() {
        assert_eq!(Value::DateTimeSeconds(0).to_string(), "1970-01-01T00:00:00");
        assert_eq!(
            Value::DateTimeSeconds(u32::MAX).to_string(),
            "2106-02-07T06:28:15"
        );
        assert_eq!(
            Value::DateTimeSeconds(951_782_400).to_string(),
            "2000-02-29T00:00:00"
        );
        // RFC 7373 section 4.8's example.
        assert_eq!(
            Value::DateTimeMilliseconds(1_352_140_261_135).to_string(),
            "2012-11-05T18:31:01.135"
        );
        let encoded = u32::try_from((123_456u64 << 32) / 1_000_000).unwrap();
        assert_eq!(
            Value::DateTimeMicroseconds(ntp(1_700_000_000, encoded)).to_string(),
            "2023-11-14T22:13:20.123456"
        );
        assert_eq!(
            Value::DateTimeNanoseconds(ntp(1_700_000_000, 1 << 31)).to_string(),
            "2023-11-14T22:13:20.500000000"
        );
    }

    #[test]
    fn ntp_timestamps_are_in_their_first_era() {
        let epoch = NtpTimestamp {
            seconds: 0,
            fraction: 0,
        };
        assert_eq!(
            Value::DateTimeMicroseconds(epoch).to_string(),
            "1900-01-01T00:00:00.000000"
        );
        assert_eq!(
            Value::DateTimeNanoseconds(NtpTimestamp {
                seconds: 5_097_600,
                fraction: 0
            })
            .to_string(),
            "1900-03-01T00:00:00.000000000"
        );
        assert_eq!(
            Value::DateTimeNanoseconds(ntp(1_700_000_000, u32::MAX)).to_string(),
            "2023-11-14T22:13:21.000000000"
        );
    }

    #[test]
    fn years_past_9999_take_more_digits() {
        assert_eq!(
            Value::DateTimeMilliseconds(253_402_300_799_999).to_string(),
            "9999-12-31T23:59:59.999"
        );
        assert_eq!(
            Value::DateTimeMilliseconds(253_402_300_800_000).to_string(),
            "10000-01-01T00:00:00.000"
        );
    }

    #[test]
    fn lists_and_null_have_no_textual_form() {
        let list = BasicList {
            semantic: ListSemantic::AllOf,
            field: FieldSpecifier {
                information_element_id: 1,
                field_length: 4,
                enterprise_number: None,
            },
            values: vec![Value::Unsigned32(1)],
        };
        assert_eq!(Value::BasicList(Box::new(list)).to_string(), "");
        assert_eq!(Value::Null.to_string(), "");
    }
}
