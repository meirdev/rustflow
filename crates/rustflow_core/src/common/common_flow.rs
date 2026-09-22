use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::Serialize;
use strum::Display;

use crate::common::serializer::serialize_mac_as_text;
use crate::common::timeout_map::TimeoutHashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowType {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

/// Key for sampling rate cache: (exporter_address,
/// source_id/observation_domain_id)
pub type SamplingRateCacheKey = (IpAddr, u32);

pub struct SamplingRateCache {
    cache: TimeoutHashMap<SamplingRateCacheKey, u32>,
}

impl SamplingRateCache {
    pub fn new(timeout: Duration) -> Self {
        Self {
            cache: TimeoutHashMap::new(timeout),
        }
    }

    pub fn get(&self, key: &SamplingRateCacheKey) -> Option<u32> {
        self.cache.get(key).copied()
    }

    pub fn set(&mut self, key: SamplingRateCacheKey, rate: u32) {
        self.cache.insert(key, rate);
    }

    pub fn cleanup(&mut self) {
        self.cache.cleanup();
    }
}

impl Default for SamplingRateCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

#[macro_export]
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

#[derive(Debug, Clone, Serialize)]
pub struct CommonFlow {
    pub flow_type: FlowType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_received_ns: Option<i64>,

    pub sequence_num: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_rate: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampler_address: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_flow_start_ns: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_flow_end_ns: Option<i64>,

    pub bytes: u64,

    pub packets: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_addr: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_addr: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_mac_as_text")]
    pub src_mac: Option<MacAddr6>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_mac_as_text")]
    pub dst_mac: Option<MacAddr6>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub etype: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_if: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_if: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_tos: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_ttl: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_flow_label: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_offset: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_as: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_as: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_net: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_net: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgp_next_hop: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_vlan: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_vlan: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_domain_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u16>,
}

impl Default for CommonFlow {
    fn default() -> Self {
        Self {
            flow_type: FlowType::NetflowV5,
            time_received_ns: None,
            sequence_num: 0,
            sampling_rate: None,
            sampler_address: None,
            time_flow_start_ns: None,
            time_flow_end_ns: None,
            bytes: 0,
            packets: 0,
            src_addr: None,
            dst_addr: None,
            src_mac: None,
            dst_mac: None,
            etype: None,
            proto: None,
            src_port: None,
            dst_port: None,
            in_if: None,
            out_if: None,
            ip_tos: None,
            ip_ttl: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            ipv6_flow_label: None,
            fragment_id: None,
            fragment_offset: None,
            src_as: None,
            dst_as: None,
            next_hop: None,
            src_net: None,
            dst_net: None,
            bgp_next_hop: None,
            src_vlan: None,
            dst_vlan: None,
            observation_domain_id: None,
            template_id: None,
        }
    }
}

impl CommonFlow {
    pub fn new(flow_type: FlowType) -> Self {
        Self {
            flow_type,
            ..Default::default()
        }
    }

    pub fn with_time_received(mut self, time: DateTime<Utc>) -> Self {
        self.time_received_ns = Some(time.timestamp_nanos_opt().unwrap_or(0));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! names {
        ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
            /// Compiles only while the list and the struct name the same
            /// fields.
            fn names(flow: &CommonFlow) -> Vec<&'static str> {
                let CommonFlow { $( $name, )* } = flow;
                $( let _ = $name; )*
                vec![$( stringify!($name), )*]
            }
        };
    }
    for_each_flow_field!(names);

    #[test]
    fn list_names_every_field_of_the_struct() {
        let names = names(&CommonFlow::new(FlowType::Ipfix));
        assert_eq!(names.len(), 37);
        assert_eq!(names[0], "flow_type");
        assert_eq!(names[36], "template_id");
    }
}
