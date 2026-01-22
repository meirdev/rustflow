use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: DateTime<Utc>,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u16,
    pub sampling_interval: u16,
    pub flow_records: Vec<FlowRecord>,
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
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub srcport: u16,
    pub dstport: u16,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
}
