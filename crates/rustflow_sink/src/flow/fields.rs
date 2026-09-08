//! The one list of a flow's columns.
//!
//! `for_each_flow_field!` is the single place the columns are named: one
//! line per field with its kind and presence. Every consumer expands it at
//! compile time with its own callback macro:
//!
//! - this module generates [`visit`], a runtime walk that hands each column
//!   to a closure as a [`Value`] (CSV uses it);
//! - `parquet.rs` generates typed Arrow builders from it;
//! - `protobuf.rs` generates the wire encoder from it, tags by position.
//!
//! The list states three facts about a flow and nothing about any output
//! format: name, kind, and whether the column can be null. How a kind is
//! written is decided by each encoder in its own file.

use std::net::IpAddr;

use macaddr::MacAddr6;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

/// The columns of a flow, in output order: `name: Kind presence`.
///
/// Kinds: `FlowType`, `Timestamp` (nanoseconds since the Unix epoch), `U8`,
/// `U16`, `U32`, `U64`, `Ip`, `Mac`. Presence: `required`, or `optional`
/// for an `Option` field in `CommonFlow`.
///
/// Append only. Every consumer destructures `CommonFlow` with this list and
/// no `..`, so a field added to core fails to compile until it has a line
/// here; the protobuf wire tags are positional, so a line inserted in the
/// middle would renumber them (the protobuf tests pin the contract).
macro_rules! for_each_flow_field {
    ($callback:ident) => {
        $callback! {
            flow_type: FlowType required,
            time_received_ns: Timestamp optional,
            sequence_num: U32 required,
            sampling_rate: U32 optional,
            sampler_address: Ip optional,
            time_flow_start_ns: Timestamp optional,
            time_flow_end_ns: Timestamp optional,
            bytes: U64 required,
            packets: U64 required,
            src_addr: Ip optional,
            dst_addr: Ip optional,
            src_mac: Mac optional,
            dst_mac: Mac optional,
            etype: U16 optional,
            proto: U8 optional,
            src_port: U16 optional,
            dst_port: U16 optional,
            in_if: U32 optional,
            out_if: U32 optional,
            ip_tos: U8 optional,
            ip_ttl: U8 optional,
            tcp_flags: U16 optional,
            icmp_type: U8 optional,
            icmp_code: U8 optional,
            ipv6_flow_label: U32 optional,
            fragment_id: U32 optional,
            fragment_offset: U16 optional,
            src_as: U32 optional,
            dst_as: U32 optional,
            next_hop: Ip optional,
            src_net: U8 optional,
            dst_net: U8 optional,
            bgp_next_hop: Ip optional,
            src_vlan: U16 optional,
            dst_vlan: U16 optional,
            observation_domain_id: U32 optional,
            template_id: U16 optional,
        }
    };
}
pub(crate) use for_each_flow_field;

/// Column metadata. `nullable` follows from the field's presence in the
/// list, not from any output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub nullable: bool,
}

/// The typed value of one column. Each variant is a kind an encoder must
/// know how to write; the `Option` inside carries presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    FlowType(FlowType),
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
    /// Nanoseconds since the Unix epoch. Kept apart from `U64` so a
    /// columnar format can type it as a timestamp.
    TimestampNs(Option<i64>),
    Ip(Option<IpAddr>),
    Mac(Option<MacAddr6>),
}

macro_rules! is_nullable {
    (required) => {
        false
    };
    (optional) => {
        true
    };
}

/// A field's value as a [`Value`], for each kind and presence in the list.
macro_rules! as_value {
    (FlowType required, $v:expr) => {
        Value::FlowType($v)
    };
    (Timestamp optional, $v:expr) => {
        Value::TimestampNs($v)
    };
    (U8 optional, $v:expr) => {
        Value::U8($v)
    };
    (U16 optional, $v:expr) => {
        Value::U16($v)
    };
    (U32 optional, $v:expr) => {
        Value::U32($v)
    };
    (U32 required, $v:expr) => {
        Value::U32(Some($v))
    };
    (U64 required, $v:expr) => {
        Value::U64(Some($v))
    };
    (Ip optional, $v:expr) => {
        Value::Ip($v)
    };
    (Mac optional, $v:expr) => {
        Value::Mac($v)
    };
}

macro_rules! define_visit {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        /// Walk every column of a flow, in output order.
        pub fn visit<E>(
            flow: &CommonFlow,
            mut f: impl FnMut(Column, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            let CommonFlow { $( $name, )* } = flow;
            $(
                f(
                    Column { name: stringify!($name), nullable: is_nullable!($presence) },
                    as_value!($kind $presence, *$name),
                )?;
            )*
            Ok(())
        }
    };
}
for_each_flow_field!(define_visit);

/// Column metadata alone, e.g. for a CSV header.
pub fn columns() -> impl ExactSizeIterator<Item = Column> {
    columns_with_values().map(|(c, _)| c)
}

/// Column metadata plus a value of the right kind, taken from a default
/// flow. The values are placeholders; their kinds are what matter.
pub fn columns_with_values() -> impl ExactSizeIterator<Item = (Column, Value)> {
    let mut out = Vec::with_capacity(40);
    let Ok(()) = visit(&CommonFlow::new(FlowType::Ipfix), |c, v| {
        out.push((c, v));
        Ok::<(), std::convert::Infallible>(())
    });
    out.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header `rustflow_collect` writes today, verbatim. The list must
    /// never drift from it.
    const TODAYS_HEADERS: &[&str] = &[
        "flow_type",
        "time_received_ns",
        "sequence_num",
        "sampling_rate",
        "sampler_address",
        "time_flow_start_ns",
        "time_flow_end_ns",
        "bytes",
        "packets",
        "src_addr",
        "dst_addr",
        "src_mac",
        "dst_mac",
        "etype",
        "proto",
        "src_port",
        "dst_port",
        "in_if",
        "out_if",
        "ip_tos",
        "ip_ttl",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
        "ipv6_flow_label",
        "fragment_id",
        "fragment_offset",
        "src_as",
        "dst_as",
        "next_hop",
        "src_net",
        "dst_net",
        "bgp_next_hop",
        "src_vlan",
        "dst_vlan",
        "observation_domain_id",
        "template_id",
    ];

    #[test]
    fn column_order_matches_todays_header() {
        let names: Vec<&str> = columns().map(|c| c.name).collect();
        assert_eq!(names, TODAYS_HEADERS);
    }

    #[test]
    fn only_the_non_option_fields_are_required() {
        let required: Vec<&str> = columns().filter(|c| !c.nullable).map(|c| c.name).collect();
        assert_eq!(required, ["flow_type", "sequence_num", "bytes", "packets"]);
    }

    #[test]
    fn visit_reports_the_flow_values() {
        let flow = crate::test_support::sample_flow();
        let mut seen = Vec::new();
        let Ok(()) = visit(&flow, |c, v| {
            seen.push((c.name, v));
            Ok::<(), std::convert::Infallible>(())
        });
        assert_eq!(seen[7], ("bytes", Value::U64(Some(1234))));
        assert_eq!(seen[9], ("src_addr", Value::Ip(flow.src_addr)));
        assert_eq!(seen[10], ("dst_addr", Value::Ip(None)));
        assert_eq!(seen[15], ("src_port", Value::U16(Some(443))));
    }

    #[test]
    fn visit_stops_at_the_first_error() {
        let flow = crate::test_support::sample_flow();
        let mut count = 0;
        let result = visit(&flow, |c, _| {
            count += 1;
            if c.name == "bytes" {
                Err("stop")
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err("stop"));
        assert_eq!(count, 8);
    }
}
