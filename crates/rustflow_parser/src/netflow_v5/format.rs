use std::net::Ipv4Addr;

use serde::Serialize;

pub const NETFLOW_V5_VERSION: u16 = 5;

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV5 {
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u16,
    pub sampling_interval: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRecord {
    pub srcaddr: Ipv4Addr,
    pub dstaddr: Ipv4Addr,
    pub nexthop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_ockts: u32,
    pub first: u32,
    pub last: u32,
    pub srcport: u16,
    pub dstport: u16,
    pub pad1: u8,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}
