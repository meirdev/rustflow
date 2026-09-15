use std::collections::HashMap;
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;

use prost::Message;
use rustflow_core::common::common_flow::CommonFlow;

use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// `rustflow.CommonFlow` of `proto/rustflow.proto`. Tags are the wire
/// contract: new fields get tags from 39, 38 is the enrichment map.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowMessage {
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
    /// Fields added by `--enrich`, keyed by their output name.
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

impl FlowMessage {
    /// No `..` in the destructure: a field added to `CommonFlow` fails to
    /// compile until it is mapped here.
    pub fn from_flow(flow: &CommonFlow, names: &[String], enriched: &Enriched) -> Self {
        let CommonFlow {
            flow_type,
            time_received_ns,
            sequence_num,
            sampling_rate,
            sampler_address,
            time_flow_start_ns,
            time_flow_end_ns,
            bytes,
            packets,
            src_addr,
            dst_addr,
            src_mac,
            dst_mac,
            etype,
            proto,
            src_port,
            dst_port,
            in_if,
            out_if,
            ip_tos,
            ip_ttl,
            tcp_flags,
            icmp_type,
            icmp_code,
            ipv6_flow_label,
            fragment_id,
            fragment_offset,
            src_as,
            dst_as,
            next_hop,
            src_net,
            dst_net,
            bgp_next_hop,
            src_vlan,
            dst_vlan,
            observation_domain_id,
            template_id,
        } = flow;
        Self {
            flow_type: flow_type.to_string(),
            time_received_ns: *time_received_ns,
            sequence_num: *sequence_num,
            sampling_rate: *sampling_rate,
            sampler_address: sampler_address.map(ip_bytes),
            time_flow_start_ns: *time_flow_start_ns,
            time_flow_end_ns: *time_flow_end_ns,
            bytes: *bytes,
            packets: *packets,
            src_addr: src_addr.map(ip_bytes),
            dst_addr: dst_addr.map(ip_bytes),
            src_mac: src_mac.map(|m| m.into_array().to_vec()),
            dst_mac: dst_mac.map(|m| m.into_array().to_vec()),
            etype: etype.map(u32::from),
            proto: proto.map(u32::from),
            src_port: src_port.map(u32::from),
            dst_port: dst_port.map(u32::from),
            in_if: *in_if,
            out_if: *out_if,
            ip_tos: ip_tos.map(u32::from),
            ip_ttl: ip_ttl.map(u32::from),
            tcp_flags: tcp_flags.map(u32::from),
            icmp_type: icmp_type.map(u32::from),
            icmp_code: icmp_code.map(u32::from),
            ipv6_flow_label: *ipv6_flow_label,
            fragment_id: *fragment_id,
            fragment_offset: fragment_offset.map(u32::from),
            src_as: *src_as,
            dst_as: *dst_as,
            next_hop: next_hop.map(ip_bytes),
            src_net: src_net.map(u32::from),
            dst_net: dst_net.map(u32::from),
            bgp_next_hop: bgp_next_hop.map(ip_bytes),
            src_vlan: src_vlan.map(u32::from),
            dst_vlan: dst_vlan.map(u32::from),
            observation_domain_id: *observation_domain_id,
            template_id: template_id.map(u32::from),
            enriched: names
                .iter()
                .zip(enriched.iter())
                .filter_map(|(name, value)| Some((name.clone(), value?.to_owned())))
                .collect(),
        }
    }
}

/// Length-delimited protobuf, one [`FlowMessage`] per record.
pub struct Protobuf {
    out: BufWriter<Writer>,
    names: Vec<String>,
    buf: Vec<u8>,
}

impl Protobuf {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            names: enriched_fields.to_vec(),
            buf: Vec::with_capacity(512),
        })
    }
}

impl Encoder for Protobuf {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.buf.clear();
        FlowMessage::from_flow(flow, &self.names, enriched)
            .encode_length_delimited(&mut self.buf)
            .map_err(io::Error::other)?;
        self.out.write_all(&self.buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
