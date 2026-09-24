use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rustflow_core::ipfix::parser::{DataRecord, FieldValue};

use crate::ipfix::template::{FLOW_IPV4_TEMPLATE_ID, FLOW_IPV6_TEMPLATE_ID};

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
    pub flow_end_reason: u8,
}

impl FlowData {
    pub fn template_id(&self) -> u16 {
        match self.source_ip {
            IpAddr::V4(_) => FLOW_IPV4_TEMPLATE_ID,
            IpAddr::V6(_) => FLOW_IPV6_TEMPLATE_ID,
        }
    }

    fn ip_version(&self) -> u8 {
        match self.source_ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            address(self.source_ip),
            address(self.destination_ip),
            FieldValue::Unsigned8(self.ip_version()),
            FieldValue::Unsigned8(self.protocol),
            FieldValue::Unsigned16(self.source_port),
            FieldValue::Unsigned16(self.destination_port),
            FieldValue::Unsigned64(self.octet_count),
            FieldValue::Unsigned64(self.packet_count),
            FieldValue::Unsigned16(self.tcp_flags),
            FieldValue::DateTimeMilliseconds(self.flow_start),
            FieldValue::DateTimeMilliseconds(self.flow_end),
            FieldValue::Unsigned8(self.flow_end_reason),
        ])
    }
}

fn address(ip: IpAddr) -> FieldValue {
    match ip {
        IpAddr::V4(v4) => FieldValue::Ipv4Address(v4),
        IpAddr::V6(v6) => FieldValue::Ipv6Address(v6),
    }
}

#[derive(Debug)]
pub struct OptionsData {
    pub observation_domain_id: u32,
    pub sampling_packet_interval: u32,
}

impl OptionsData {
    pub fn new(observation_domain_id: u32, sampling_packet_interval: u32) -> Self {
        Self {
            observation_domain_id,
            sampling_packet_interval,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Unsigned32(self.observation_domain_id),
            FieldValue::Unsigned32(self.sampling_packet_interval),
        ])
    }
}
