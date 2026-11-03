use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since 1970 of `time`, if it is after 1970 and fits.
pub(crate) fn unix_millis(time: SystemTime) -> Option<u64> {
    let since_epoch = time.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since_epoch.as_millis()).ok()
}

/// Milliseconds since 1970 of `uptime_ms`, a time on an exporter that had
/// been up `sys_uptime_ms` at `export_time_ms`.
///
/// Uptimes wrap after about 49.7 days, so their difference is taken modulo
/// 2^32 and read as signed: a flow that started before the wrap lies in the
/// past, and one stamped a little after the export time just after it.
pub(crate) fn uptime_to_unix_millis(
    export_time_ms: u64,
    sys_uptime_ms: u32,
    uptime_ms: u32,
) -> Option<u64> {
    let before_export = sys_uptime_ms.wrapping_sub(uptime_ms).cast_signed();
    export_time_ms.checked_add_signed(-i64::from(before_export))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT_TIME_MS: u64 = 1_700_000_000_000;

    #[test]
    fn uptimes_keep_their_signed_offset_from_the_export_time() {
        for (uptime_ms, expected) in [
            (0, 1_699_999_998_766),
            (1_000, 1_699_999_999_766),
            (1_234, 1_700_000_000_000),
            (1_500, 1_700_000_000_266),
        ] {
            assert_eq!(
                uptime_to_unix_millis(EXPORT_TIME_MS, 1_234, uptime_ms),
                Some(expected)
            );
        }
    }

    #[test]
    fn uptimes_span_the_uptime_wrap() {
        assert_eq!(
            uptime_to_unix_millis(EXPORT_TIME_MS, 5_000, u32::MAX - 4_999),
            Some(1_699_999_990_000)
        );
    }

    #[test]
    fn times_before_1970_have_no_unix_millis() {
        assert_eq!(uptime_to_unix_millis(1_000, 5_000, 0), None);
        assert_eq!(
            unix_millis(UNIX_EPOCH - std::time::Duration::from_secs(1)),
            None
        );
    }
}
