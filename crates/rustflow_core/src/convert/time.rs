use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::value::Value;

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

/// What a packet's relative times are relative to.
#[derive(Debug, Clone, Copy)]
pub struct TimeBase {
    pub export_time_ms: u64,
    pub uptime: Uptime,
}

/// What an exporter's uptime counts from.
#[derive(Debug, Clone, Copy)]
pub enum Uptime {
    /// NetFlow v9: the uptime the header gives at the export time.
    AtExport(u32),
    /// IPFIX: the exporter's last (re)initialization, if an options record
    /// gave it.
    BootedAt(Option<u64>),
}

impl TimeBase {
    /// The absolute element a relative time's values become, if they can
    /// be made absolute; `None` for any other element.
    pub(crate) fn absolute_element(&self, element: ElementId) -> Option<ElementId> {
        match element {
            iana::FLOW_START_SYS_UP_TIME => self
                .uptimes_convert()
                .then_some(iana::FLOW_START_MILLISECONDS),
            iana::FLOW_END_SYS_UP_TIME => self
                .uptimes_convert()
                .then_some(iana::FLOW_END_MILLISECONDS),
            iana::FLOW_START_DELTA_MICROSECONDS => Some(iana::FLOW_START_MILLISECONDS),
            iana::FLOW_END_DELTA_MICROSECONDS => Some(iana::FLOW_END_MILLISECONDS),
            _ => None,
        }
    }

    /// Makes a relative time's value absolute, giving the element it then
    /// is; any other element, or a value that cannot be made absolute, is
    /// left as it is.
    pub(crate) fn make_absolute(&self, element: ElementId, value: &mut Value) -> ElementId {
        match self.absolute_element(element) {
            Some(absolute) => match self.absolute_value(element, value) {
                Some(time) => {
                    *value = time;
                    absolute
                }
                None => element,
            },
            None => element,
        }
    }

    pub(crate) fn uptimes_convert(&self) -> bool {
        match self.uptime {
            Uptime::AtExport(_) => true,
            Uptime::BootedAt(boot_ms) => boot_ms.is_some(),
        }
    }

    /// The absolute time a value of `relative` stands for; `None` for a
    /// value that cannot be made absolute.
    pub(crate) fn absolute_value(&self, relative: ElementId, value: &Value) -> Option<Value> {
        let millis = match relative {
            iana::FLOW_START_SYS_UP_TIME | iana::FLOW_END_SYS_UP_TIME => self.uptime(value)?,
            iana::FLOW_START_DELTA_MICROSECONDS | iana::FLOW_END_DELTA_MICROSECONDS => {
                self.before_export(value)?
            }
            _ => return None,
        };
        Some(Value::DateTimeMilliseconds(millis))
    }

    fn uptime(&self, value: &Value) -> Option<u64> {
        let uptime_ms = value.as_u64()?;
        match self.uptime {
            Uptime::AtExport(sys_uptime_ms) => uptime_to_unix_millis(
                self.export_time_ms,
                sys_uptime_ms,
                u32::try_from(uptime_ms).ok()?,
            ),
            Uptime::BootedAt(boot_ms) => boot_ms?.checked_add(uptime_ms),
        }
    }

    /// A time given as microseconds before the export time.
    fn before_export(&self, value: &Value) -> Option<u64> {
        let export_time_us = self.export_time_ms.checked_mul(1_000)?;
        Some(export_time_us.checked_sub(value.as_u64()?)? / 1_000)
    }
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
