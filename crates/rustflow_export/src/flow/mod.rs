use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::ipfix::data::FlowData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowEndReason {
    IdleTimeout = 1,
    ActiveTimeout = 2,
    ForcedEnd = 4,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
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
    pub flow_end_reason: Option<FlowEndReason>,
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
            flow_end_reason: None,
        }
    }

    fn ended(&self, reason: FlowEndReason) -> Self {
        Self {
            flow_end_reason: Some(reason),
            ..self.clone()
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
            source_ip: self.key.source_ip,
            destination_ip: self.key.destination_ip,
            protocol: self.key.protocol,
            source_port: self.key.source_port,
            destination_port: self.key.destination_port,
            octet_count: self.octet_count,
            packet_count: self.packet_count,
            tcp_flags: self.tcp_flags,
            flow_start: self.flow_start,
            flow_end: self.flow_end,
            flow_end_reason: self.flow_end_reason.map_or(0, |reason| reason as u8),
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

            let reason = if age >= active_timeout {
                FlowEndReason::ActiveTimeout
            } else if idle_time >= inactive_timeout {
                FlowEndReason::IdleTimeout
            } else {
                return true;
            };
            expired.push(flow.ended(reason));
            false
        });

        expired
    }

    /// Every flow, ended by force (shutdown).
    pub fn export_all(&mut self) -> Vec<Flow> {
        self.flows
            .drain()
            .map(|(_, flow)| flow.ended(FlowEndReason::ForcedEnd))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}
