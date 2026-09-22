use std::net::IpAddr;

use crate::common::common_flow::{CommonFlow, FlowType};
use crate::netflow_v5::parser::{FlowRecord as V5FlowRecord, Header as V5Header};

pub struct NetFlowV5Context<'a> {
    pub header: &'a V5Header,
    pub sampler_address: Option<IpAddr>,
}

impl NetFlowV5Context<'_> {
    /// In NetFlow v5, `first` and `last` are system uptime values in
    /// milliseconds. We convert them to absolute time using:
    /// `absolute_time = unix_time - (sys_uptime - uptime_value)`
    fn uptime_to_absolute_ns(&self, uptime_ms: i64) -> Option<i64> {
        let unix_time_ns =
            (self.header.unix_secs as i64) * 1_000_000_000 + (self.header.unix_nsecs as i64);
        let sys_uptime_ms = self.header.sys_uptime.timestamp_millis();
        let offset_ms = sys_uptime_ms - uptime_ms;
        Some(unix_time_ns - (offset_ms * 1_000_000))
    }

    pub fn convert(&self, record: &V5FlowRecord) -> CommonFlow {
        CommonFlow {
            flow_type: FlowType::NetflowV5,
            time_received_ns: None,
            sequence_num: self.header.flow_sequence,
            sampling_rate: Some(self.header.sampling_interval as u32),
            sampler_address: self.sampler_address,
            time_flow_start_ns: self.uptime_to_absolute_ns(record.first.timestamp_millis()),
            time_flow_end_ns: self.uptime_to_absolute_ns(record.last.timestamp_millis()),
            bytes: record.d_ockts as u64,
            packets: record.d_pkts as u64,
            src_addr: Some(IpAddr::V4(record.srcaddr)),
            dst_addr: Some(IpAddr::V4(record.dstaddr)),
            src_mac: None,
            dst_mac: None,
            etype: Some(0x0800),
            proto: Some(record.prot),
            src_port: Some(record.srcport),
            dst_port: Some(record.dstport),
            in_if: Some(record.input as u32),
            out_if: Some(record.output as u32),
            ip_tos: Some(record.tos),
            ip_ttl: None,
            tcp_flags: Some(u16::from(record.tcp_flags)),
            icmp_type: None,
            icmp_code: None,
            ipv6_flow_label: None,
            fragment_id: None,
            fragment_offset: None,
            src_as: Some(record.src_as as u32),
            dst_as: Some(record.dst_as as u32),
            next_hop: Some(IpAddr::V4(record.nexthop)),
            src_net: Some(record.src_mask),
            dst_net: Some(record.dst_mask),
            bgp_next_hop: None,
            src_vlan: None,
            dst_vlan: None,
            observation_domain_id: None,
            template_id: None, // NetFlow v5 has no templates
        }
    }
}
