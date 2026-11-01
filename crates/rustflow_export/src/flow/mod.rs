pub mod parse;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

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

/// When a packet was seen: its capture time, which is exported, and the
/// monotonic clock, which timeouts are measured on so that a step of the wall
/// clock cannot stall or rush them.
#[derive(Debug, Clone, Copy)]
pub struct Seen {
    pub time: DateTime<Utc>,
    pub instant: Instant,
}

#[cfg(test)]
impl Seen {
    pub fn now() -> Self {
        Self {
            time: Utc::now(),
            instant: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
    first_seen: Instant,
    last_seen: Instant,
    pub flow_end_reason: Option<FlowEndReason>,
}

impl Flow {
    pub fn new(key: FlowKey, seen: Seen) -> Self {
        Self {
            key,
            octet_count: 0,
            packet_count: 0,
            tcp_flags: 0,
            flow_start: seen.time,
            flow_end: seen.time,
            first_seen: seen.instant,
            last_seen: seen.instant,
            flow_end_reason: None,
        }
    }

    fn ended(&self, reason: FlowEndReason) -> Self {
        Self {
            flow_end_reason: Some(reason),
            ..self.clone()
        }
    }

    pub fn update(&mut self, packet_size: u64, tcp_flags: u16, seen: Seen) {
        self.octet_count += packet_size;
        self.packet_count += 1;
        self.tcp_flags |= tcp_flags;
        self.flow_end = seen.time;
        self.last_seen = seen.instant;
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
    active_timeout: Duration,
    inactive_timeout: Duration,
    max_flows: usize,
    /// Flows ended to make room, waiting to be exported.
    evicted: Vec<Flow>,
}

impl FlowCache {
    pub fn new(active_timeout: u64, inactive_timeout: u64, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            active_timeout: Duration::from_secs(active_timeout),
            inactive_timeout: Duration::from_secs(inactive_timeout),
            max_flows,
            evicted: Vec::new(),
        }
    }

    pub fn update_flow(&mut self, key: FlowKey, packet_size: u64, tcp_flags: u16, seen: Seen) {
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.update(packet_size, tcp_flags, seen);
            return;
        }
        if self.flows.len() >= self.max_flows {
            self.evict_idle_longest();
        }
        let mut flow = Flow::new(key.clone(), seen);
        flow.update(packet_size, tcp_flags, seen);
        self.flows.insert(key, flow);
    }

    /// Ends the flows idle longest, a batch of [`EVICTION_FRACTION`] of the
    /// cache, as lacking resources (RFC 5102).
    fn evict_idle_longest(&mut self) {
        let count = (self.max_flows / EVICTION_FRACTION).max(1);
        let mut ends: Vec<_> = self.flows.values().map(|flow| flow.last_seen).collect();
        let cutoff = *ends.select_nth_unstable(count - 1).1;

        let evicted = &mut self.evicted;
        self.flows.retain(|_, flow| {
            if flow.last_seen > cutoff {
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

    /// The flows that timed out by `now`, and those ended to make room.
    pub fn check_expired_flows(&mut self, now: Instant) -> Vec<Flow> {
        let mut expired = std::mem::take(&mut self.evicted);

        let active_timeout = self.active_timeout;
        let inactive_timeout = self.inactive_timeout;

        self.flows.retain(|_, flow| {
            let age = now.saturating_duration_since(flow.first_seen);
            let idle_time = now.saturating_duration_since(flow.last_seen);

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
        let now = Instant::now();
        for port in 0..ports {
            cache.update_flow(key(port), 100, 0, Seen::now());
            cache.flows.get_mut(&key(port)).unwrap().last_seen =
                now + Duration::from_secs(u64::from(port));
        }
        cache
    }

    #[test]
    fn a_full_cache_ends_the_flows_idle_longest() {
        let mut cache = full_cache(16);
        cache.update_flow(key(16), 100, 0, Seen::now());

        assert_eq!(cache.len(), 15);
        assert!(cache.has_evicted());
        let mut ended: Vec<_> = cache
            .check_expired_flows(Instant::now())
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
        cache.update_flow(key(8), 100, 0, Seen::now());

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
            cache.update_flow(key(port), 100, 0, Seen::now());
        }
        assert!(cache.flows.capacity() >= 50_000);

        assert_eq!(cache.check_expired_flows(Instant::now()).len(), 50_000);
        assert!(cache.flows.capacity() < 1024);
    }

    #[test]
    fn timeouts_follow_the_monotonic_clock_not_the_capture_time() {
        let mut cache = FlowCache::new(60, 15, 16);
        let start = Instant::now();
        // Capture times far before and after the monotonic clock's view.
        let long_ago = DateTime::UNIX_EPOCH;
        let tomorrow = Utc::now() + chrono::TimeDelta::days(1);
        for (port, time) in [(1, long_ago), (2, tomorrow)] {
            let seen = Seen {
                time,
                instant: start,
            };
            cache.update_flow(key(port), 100, 0, seen);
        }

        assert!(
            cache
                .check_expired_flows(start + Duration::from_secs(14))
                .is_empty()
        );
        let mut ended = cache.check_expired_flows(start + Duration::from_secs(15));
        ended.sort_by_key(|flow| flow.key.source_port);
        assert_eq!(ended.len(), 2);
        assert!(
            ended
                .iter()
                .all(|flow| flow.flow_end_reason == Some(FlowEndReason::IdleTimeout))
        );
        assert_eq!(ended[0].flow_start, long_ago);
        assert_eq!(ended[1].flow_end, tomorrow);
    }
}
