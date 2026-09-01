use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock};

use chrono::{DateTime, Utc};
use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{DataRecord, FieldValue};

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ipv4: Ipv4Addr,
    pub destination_ipv4: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
}

impl FlowData {
    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            FieldValue::Ipv4Address(self.source_ipv4),
            FieldValue::Ipv4Address(self.destination_ipv4),
            FieldValue::Unsigned8(self.protocol),
            FieldValue::Unsigned16(self.source_port),
            FieldValue::Unsigned16(self.destination_port),
            FieldValue::Unsigned64(self.octets),
            FieldValue::Unsigned64(self.packets),
            FieldValue::Unsigned16(self.tcp_flags),
            FieldValue::DateTimeMilliseconds(self.flow_start),
            FieldValue::DateTimeMilliseconds(self.flow_end),
        ])
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
