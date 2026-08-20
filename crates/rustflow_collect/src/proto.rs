use std::collections::HashMap;
use std::net::IpAddr;

use rustflow_core::common::common_flow::CommonFlow as Flow;

/// A flow record, wire-compatible with `rustflow.CommonFlow`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommonFlow {
    #[prost(string, tag = "1")]
    pub flow_type: String,

    #[prost(int64, optional, tag = "2")]
    pub time_received_ns: Option<i64>,
    #[prost(uint32, tag = "3")]
    pub sequence_num: u32,
    #[prost(uint32, optional, tag = "4")]
    pub sampling_rate: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub sampler_address: Option<Vec<u8>>,

    #[prost(int64, optional, tag = "6")]
    pub time_flow_start_ns: Option<i64>,
    #[prost(int64, optional, tag = "7")]
    pub time_flow_end_ns: Option<i64>,

    #[prost(uint64, tag = "8")]
    pub bytes: u64,
    #[prost(uint64, tag = "9")]
    pub packets: u64,

    #[prost(bytes = "vec", optional, tag = "10")]
    pub src_addr: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub dst_addr: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "12")]
    pub src_mac: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub dst_mac: Option<Vec<u8>>,

    #[prost(uint32, optional, tag = "14")]
    pub etype: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub proto: Option<u32>,
    #[prost(uint32, optional, tag = "16")]
    pub src_port: Option<u32>,
    #[prost(uint32, optional, tag = "17")]
    pub dst_port: Option<u32>,
    #[prost(uint32, optional, tag = "18")]
    pub in_if: Option<u32>,
    #[prost(uint32, optional, tag = "19")]
    pub out_if: Option<u32>,
    #[prost(uint32, optional, tag = "20")]
    pub ip_tos: Option<u32>,
    #[prost(uint32, optional, tag = "21")]
    pub ip_ttl: Option<u32>,
    #[prost(uint32, optional, tag = "22")]
    pub tcp_flags: Option<u32>,
    #[prost(uint32, optional, tag = "23")]
    pub icmp_type: Option<u32>,
    #[prost(uint32, optional, tag = "24")]
    pub icmp_code: Option<u32>,
    #[prost(uint32, optional, tag = "25")]
    pub ipv6_flow_label: Option<u32>,
    #[prost(uint32, optional, tag = "26")]
    pub fragment_id: Option<u32>,
    #[prost(uint32, optional, tag = "27")]
    pub fragment_offset: Option<u32>,
    #[prost(uint32, optional, tag = "28")]
    pub src_as: Option<u32>,
    #[prost(uint32, optional, tag = "29")]
    pub dst_as: Option<u32>,

    #[prost(bytes = "vec", optional, tag = "30")]
    pub next_hop: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "31")]
    pub src_net: Option<u32>,
    #[prost(uint32, optional, tag = "32")]
    pub dst_net: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "33")]
    pub bgp_next_hop: Option<Vec<u8>>,

    #[prost(uint32, optional, tag = "34")]
    pub src_vlan: Option<u32>,
    #[prost(uint32, optional, tag = "35")]
    pub dst_vlan: Option<u32>,
    #[prost(uint32, optional, tag = "36")]
    pub observation_domain_id: Option<u32>,
    #[prost(uint32, optional, tag = "37")]
    pub template_id: Option<u32>,

    #[prost(map = "string, string", tag = "38")]
    pub enriched: HashMap<String, String>,
}

/// An address on the wire: 4 bytes for IPv4, 16 for IPv6.
fn ip_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

impl CommonFlow {
    pub fn from_flow(flow: &Flow, enriched: &HashMap<String, String>) -> Self {
        Self {
            flow_type: flow.flow_type.to_string(),
            time_received_ns: flow.time_received_ns,
            sequence_num: flow.sequence_num,
            sampling_rate: flow.sampling_rate,
            sampler_address: flow.sampler_address.map(ip_bytes),
            time_flow_start_ns: flow.time_flow_start_ns,
            time_flow_end_ns: flow.time_flow_end_ns,
            bytes: flow.bytes,
            packets: flow.packets,
            src_addr: flow.src_addr.map(ip_bytes),
            dst_addr: flow.dst_addr.map(ip_bytes),
            src_mac: flow.src_mac.map(|m| m.into_array().to_vec()),
            dst_mac: flow.dst_mac.map(|m| m.into_array().to_vec()),
            etype: flow.etype.map(u32::from),
            proto: flow.proto.map(u32::from),
            src_port: flow.src_port.map(u32::from),
            dst_port: flow.dst_port.map(u32::from),
            in_if: flow.in_if,
            out_if: flow.out_if,
            ip_tos: flow.ip_tos.map(u32::from),
            ip_ttl: flow.ip_ttl.map(u32::from),
            tcp_flags: flow.tcp_flags.map(u32::from),
            icmp_type: flow.icmp_type.map(u32::from),
            icmp_code: flow.icmp_code.map(u32::from),
            ipv6_flow_label: flow.ipv6_flow_label,
            fragment_id: flow.fragment_id,
            fragment_offset: flow.fragment_offset.map(u32::from),
            src_as: flow.src_as,
            dst_as: flow.dst_as,
            next_hop: flow.next_hop.map(ip_bytes),
            src_net: flow.src_net.map(u32::from),
            dst_net: flow.dst_net.map(u32::from),
            bgp_next_hop: flow.bgp_next_hop.map(ip_bytes),
            src_vlan: flow.src_vlan.map(u32::from),
            dst_vlan: flow.dst_vlan.map(u32::from),
            observation_domain_id: flow.observation_domain_id,
            template_id: flow.template_id.map(u32::from),
            enriched: enriched.clone(),
        }
    }
}
