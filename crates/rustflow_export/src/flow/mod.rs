pub mod parse;

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
    LackOfResources = 5,
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

/// The share of a full cache ended at once to make room: one scan of the
/// cache per batch, not per packet, when new flows keep arriving.
const EVICTION_FRACTION: usize = 8;

pub struct FlowCache {
    flows: HashMap<FlowKey, Flow>,
    active_timeout: TimeDelta,
    inactive_timeout: TimeDelta,
    max_flows: usize,
    /// Flows ended to make room, waiting to be exported.
    evicted: Vec<Flow>,
}

impl FlowCache {
    pub fn new(active_timeout: u64, inactive_timeout: u64, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            active_timeout: TimeDelta::seconds(active_timeout as i64),
            inactive_timeout: TimeDelta::seconds(inactive_timeout as i64),
            max_flows,
            evicted: Vec::new(),
        }
    }

    pub fn update_flow(&mut self, key: FlowKey, packet_size: u64, tcp_flags: u16) {
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.update(packet_size, tcp_flags);
            return;
        }
        if self.flows.len() >= self.max_flows {
            self.evict_idle_longest();
        }
        let mut flow = Flow::new(key.clone());
        flow.update(packet_size, tcp_flags);
        self.flows.insert(key, flow);
    }

    /// Ends the flows idle longest, a batch of [`EVICTION_FRACTION`] of the
    /// cache, as lacking resources (RFC 5102).
    fn evict_idle_longest(&mut self) {
        let count = (self.max_flows / EVICTION_FRACTION).max(1);
        let mut ends: Vec<_> = self.flows.values().map(|flow| flow.flow_end).collect();
        let cutoff = *ends.select_nth_unstable(count - 1).1;

        let evicted = &mut self.evicted;
        self.flows.retain(|_, flow| {
            if flow.flow_end > cutoff {
                return true;
            }
            evicted.push(flow.ended(FlowEndReason::LackOfResources));
            false
        });
    }

    /// Whether flows were ended to make room and wait to be exported.
    pub fn has_evicted(&self) -> bool {
        !self.evicted.is_empty()
    }

    /// The flows that timed out, and those ended to make room.
    pub fn check_expired_flows(&mut self) -> Vec<Flow> {
        let now = Utc::now();
        let mut expired = std::mem::take(&mut self.evicted);

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

        // A burst of flows leaves the table at its peak size otherwise.
        if self.flows.capacity() > 4 * self.flows.len().max(1024) {
            self.flows.shrink_to(2 * self.flows.len());
        }

        expired
    }

    /// Every flow, ended by force (shutdown), and those ended to make room.
    pub fn export_all(&mut self) -> Vec<Flow> {
        let mut flows = std::mem::take(&mut self.evicted);
        flows.extend(
            self.flows
                .drain()
                .map(|(_, flow)| flow.ended(FlowEndReason::ForcedEnd)),
        );
        flows
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(source_port: u16) -> FlowKey {
        FlowKey {
            source_ip: [10, 0, 0, 1].into(),
            destination_ip: [10, 0, 0, 2].into(),
            protocol: 6,
            source_port,
            destination_port: 80,
        }
    }

    /// A cache of `ports` flows, last seen in port order.
    fn full_cache(ports: u16) -> FlowCache {
        let mut cache = FlowCache::new(60, 15, usize::from(ports));
        let now = Utc::now();
        for port in 0..ports {
            cache.update_flow(key(port), 100, 0);
            cache.flows.get_mut(&key(port)).unwrap().flow_end =
                now + TimeDelta::seconds(i64::from(port));
        }
        cache
    }

    #[test]
    fn a_full_cache_ends_the_flows_idle_longest() {
        let mut cache = full_cache(16);
        cache.update_flow(key(16), 100, 0);

        assert_eq!(cache.len(), 15);
        assert!(cache.has_evicted());
        let mut ended: Vec<_> = cache
            .check_expired_flows()
            .into_iter()
            .map(|flow| (flow.key.source_port, flow.flow_end_reason))
            .collect();
        ended.sort_by_key(|(port, _)| *port);
        let lack = Some(FlowEndReason::LackOfResources);
        assert_eq!(ended, [(0, lack), (1, lack)]);
        assert!(!cache.has_evicted());
    }

    #[test]
    fn flows_ended_to_make_room_are_exported_at_shutdown_too() {
        let mut cache = full_cache(8);
        cache.update_flow(key(8), 100, 0);

        let flows = cache.export_all();
        assert_eq!(flows.len(), 9);
        assert_eq!(
            flows
                .iter()
                .filter(|flow| flow.flow_end_reason == Some(FlowEndReason::LackOfResources))
                .count(),
            1
        );
    }

    #[test]
    fn the_table_shrinks_once_a_burst_has_expired() {
        let mut cache = FlowCache::new(60, 0, 1 << 20);
        for port in 0..50_000 {
            cache.update_flow(key(port), 100, 0);
        }
        assert!(cache.flows.capacity() >= 50_000);

        assert_eq!(cache.check_expired_flows().len(), 50_000);
        assert!(cache.flows.capacity() < 1024);
    }
}
