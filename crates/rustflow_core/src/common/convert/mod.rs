use chrono::{DateTime, TimeDelta, Utc};

pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
pub mod packet;
pub mod sflow_v5;

pub use ipfix::{
    IpfixContext, extract_ipfix_sampler_id, extract_ipfix_sampling_rate,
    extract_ipfix_system_init_time,
};
pub use netflow_v5::NetFlowV5Context;
pub use netflow_v9::{NetFlowV9Context, extract_v9_sampler_id, extract_v9_sampling_rate};
pub use sflow_v5::SFlowV5Context;

/// Converts a NetFlow uptime stamp, the exporter's uptime in milliseconds, to
/// absolute nanoseconds, given the header's export time and uptime:
/// `absolute_time = export_time - (sys_uptime - uptime)`
fn uptime_to_absolute_ns(
    export_time: DateTime<Utc>,
    sys_uptime_ms: u32,
    uptime_ms: u32,
) -> Option<i64> {
    // The uptime is a u32 of milliseconds and wraps after about 49.7 days.
    // Take the difference modulo 2^32 and read it as signed, so a flow that
    // started before the wrap still lies in the past, and one stamped a
    // little after the header still lies just after it.
    let offset_ms = sys_uptime_ms.wrapping_sub(uptime_ms) as i32;
    export_time
        .checked_sub_signed(TimeDelta::milliseconds(i64::from(offset_ms)))?
        .timestamp_nanos_opt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_conversion_preserves_signed_millisecond_offsets() {
        let export_time = DateTime::from_timestamp_secs(1_700_000_000).unwrap();

        for (uptime_ms, expected_ns) in [
            (0, 1_699_999_998_766_000_000),
            (1_000, 1_699_999_999_766_000_000),
            (1_234, 1_700_000_000_000_000_000),
            (1_500, 1_700_000_000_266_000_000),
        ] {
            assert_eq!(
                uptime_to_absolute_ns(export_time, 1_234, uptime_ms),
                Some(expected_ns)
            );
        }
    }

    #[test]
    fn uptime_conversion_spans_the_uptime_wrap() {
        let export_time = DateTime::from_timestamp_secs(1_700_000_000).unwrap();

        assert_eq!(
            uptime_to_absolute_ns(export_time, 5_000, u32::MAX - 4_999),
            Some(1_699_999_990_000_000_000)
        );
    }
}
