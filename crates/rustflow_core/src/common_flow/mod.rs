mod fields;
mod ipfix;
mod netflow_v5;
mod netflow_v9;
mod options;
mod packet;
mod sampling;
mod sets;
mod sflow_v5;

use std::net::IpAddr;

pub use self::ipfix::from_ipfix;
pub use self::netflow_v5::from_netflow_v5;
pub use self::netflow_v9::from_netflow_v9;
pub use self::options::ExporterOptions;
pub use self::sflow_v5::from_sflow_v5;
use crate::mac_address::MacAddress;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString, strum::IntoStaticStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowType {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

#[macro_export]
macro_rules! for_each_flow_field {
    ($callback:ident) => {
        $callback! {
            flow_type: Protocol required,
            time_received_ns: Timestamp required,
            sampler_address: Ip required,
            sequence_num: U32 required,
            sampling_rate: U32 optional,
            time_flow_start_ns: Timestamp optional,
            time_flow_end_ns: Timestamp optional,
            bytes: U64 optional,
            packets: U64 optional,
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
            forwarding_status: U32 optional,
        }
    };
}

/// The Rust type of a field type in [`for_each_flow_field`].
macro_rules! flow_field_type {
    (Protocol) => {
        FlowType
    };
    (Timestamp) => {
        i64
    };
    (U8) => {
        u8
    };
    (U16) => {
        u16
    };
    (U32) => {
        u32
    };
    (U64) => {
        u64
    };
    (Ip) => {
        IpAddr
    };
    (Mac) => {
        MacAddress
    };
}

/// Defines [`CommonFlow`] and [`CommonFlow::new`] from the fields of
/// [`for_each_flow_field`], one at a time, gathering the struct's fields,
/// `new`'s parameters (the required fields) and its initializers.
macro_rules! define_common_flow {
    (@field [$($field:tt)*] [$($param:tt)*] [$($init:tt)*]) => {
        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
        pub struct CommonFlow {
            $($field)*
        }

        impl CommonFlow {
            /// A flow with the required fields set and the rest empty.
            pub fn new($($param)*) -> Self {
                Self { $($init)* }
            }
        }
    };
    (@field [$($field:tt)*] [$($param:tt)*] [$($init:tt)*]
        $name:ident: $type:ident required, $($rest:tt)*) => {
        define_common_flow!(@field
            [$($field)* pub $name: flow_field_type!($type),]
            [$($param)* $name: flow_field_type!($type),]
            [$($init)* $name,]
            $($rest)*);
    };
    (@field [$($field:tt)*] [$($param:tt)*] [$($init:tt)*]
        $name:ident: $type:ident optional, $($rest:tt)*) => {
        define_common_flow!(@field
            [$($field)*
                #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
                pub $name: Option<flow_field_type!($type)>,]
            [$($param)*]
            [$($init)* $name: None,]
            $($rest)*);
    };
    // After the `@field` arms, which it would match too.
    ($($fields:tt)*) => {
        define_common_flow!(@field [] [] [] $($fields)*);
    };
}

for_each_flow_field!(define_common_flow);
