use std::collections::HashMap;
use std::net::Ipv4Addr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::ipfix::data::FlowData;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        let now = Utc::now();
        Self {
            key,
            octet_count: 0,
            packet_count: 0,
            tcp_flags: 0,
            flow_start: now,
            flow_end: now,
        }
    }

    pub fn update(&mut self, packet_size: u64, tcp_flags: u16) {
        self.octet_count += packet_size;
        self.packet_count += 1;
        self.tcp_flags |= tcp_flags;
        self.flow_end = Utc::now();
    }

    pub fn to_flow_data(&self) -> FlowData {
        FlowData {
            source_ipv4: self.key.source_ip,
            destination_ipv4: self.key.destination_ip,
            protocol: self.key.protocol,
            source_port: self.key.source_port,
            destination_port: self.key.destination_port,
            octet_count: self.octet_count,
            packet_count: self.packet_count,
            tcp_flags: self.tcp_flags,
            flow_start: self.flow_start,
            flow_end: self.flow_end,
        }
    }
}

pub struct FlowCache {
    flows: HashMap<FlowKey, Flow>,
    active_timeout: TimeDelta,
    inactive_timeout: TimeDelta,
}

impl FlowCache {
    pub fn new(active_timeout: u64, inactive_timeout: u64) -> Self {
        Self {
            flows: HashMap::new(),
            active_timeout: TimeDelta::seconds(active_timeout as i64),
            inactive_timeout: TimeDelta::seconds(inactive_timeout as i64),
        }
    }

    pub fn update_flow(&mut self, key: FlowKey, packet_size: u64, tcp_flags: u16) {
        self.flows
            .entry(key.clone())
            .or_insert_with(|| Flow::new(key))
            .update(packet_size, tcp_flags);
    }

    pub fn check_expired_flows(&mut self) -> Vec<Flow> {
        let now = Utc::now();
        let mut expired = Vec::new();

        let active_timeout = self.active_timeout;
        let inactive_timeout = self.inactive_timeout;

        self.flows.retain(|_, flow| {
            let age = now - flow.flow_start;
            let idle_time = now - flow.flow_end;

            if age >= active_timeout || idle_time >= inactive_timeout {
                expired.push(flow.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    pub fn export_all(&mut self) -> Vec<Flow> {
        let flows: Vec<Flow> = self.flows.values().cloned().collect();
        self.flows.clear();
        flows
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}
