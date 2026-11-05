use jiff::Timestamp;

use super::{MICROSECOND_FRACTION_MASK, NTP_UNIX_EPOCH_DIFF, NtpTimestamp, Value};

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
        let fraction = self.fraction_nanos(fraction_mask, precision);
        let nanos = i128::from(seconds) * 1_000_000_000 + i128::from(fraction);
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
