use std::hash::Hash;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

#[derive(Debug)]
struct TimedEntry<V> {
    value: V,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct BoundedTimedMap<K, V> {
    map: FxHashMap<K, TimedEntry<V>>,
    capacity: usize,
    ttl: Duration,
}

impl<K: Hash + Eq + Clone, V> BoundedTimedMap<K, V> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            map: FxHashMap::default(),
            capacity,
            ttl,
        }
    }

    pub fn insert_at(&mut self, key: K, value: V, now: Instant) -> Option<V> {
        if self.capacity == 0 {
            return None;
        }
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            self.purge_expired_at(now);
            if self.map.len() >= self.capacity {
                self.evict_soonest_expiring();
            }
        }

        let entry = TimedEntry {
            value,
            expires_at: now + self.ttl,
        };
        self.map.insert(key, entry).map(|old| old.value)
    }

    pub fn get_at(&self, key: &K, now: Instant) -> Option<&V> {
        self.map
            .get(key)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| &entry.value)
    }

    pub fn get_or_insert_with_at(
        &mut self,
        key: K,
        now: Instant,
        default: impl FnOnce() -> V,
    ) -> Option<&mut V> {
        if self.get_at(&key, now).is_none() {
            self.insert_at(key.clone(), default(), now);
        }
        let entry = self.map.get_mut(&key)?;
        entry.expires_at = now + self.ttl;
        Some(&mut entry.value)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|entry| entry.value)
    }

    pub fn purge_expired_at(&mut self, now: Instant) {
        self.map.retain(|_, entry| entry.expires_at > now);
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn evict_soonest_expiring(&mut self) {
        // Only runs when the map is full of live entries and a new key arrives.
        let soonest = self
            .map
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(key, _)| key.clone());
        if let Some(key) = soonest {
            self.map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_mins(1);

    #[test]
    fn get_respects_ttl() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(4, TTL);
        map.insert_at(1, "a", t0);

        assert_eq!(map.get_at(&1, t0 + Duration::from_secs(59)), Some(&"a"));
        assert_eq!(map.get_at(&1, t0 + TTL), None);
    }

    #[test]
    fn insert_refreshes_ttl_and_returns_previous() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(4, TTL);
        map.insert_at(1, "a", t0);
        assert_eq!(
            map.insert_at(1, "b", t0 + Duration::from_secs(30)),
            Some("a")
        );

        assert_eq!(map.get_at(&1, t0 + Duration::from_secs(80)), Some(&"b"));
    }

    #[test]
    fn full_map_purges_expired_before_evicting() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(2, TTL);
        map.insert_at(1, "old", t0);
        map.insert_at(2, "live", t0 + Duration::from_secs(30));

        // Key 1 has expired by now, so it goes instead of a live entry.
        let now = t0 + Duration::from_secs(70);
        map.insert_at(3, "new", now);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get_at(&2, now), Some(&"live"));
        assert_eq!(map.get_at(&3, now), Some(&"new"));
    }

    #[test]
    fn full_map_evicts_soonest_expiring() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(2, TTL);
        map.insert_at(1, "a", t0);
        map.insert_at(2, "b", t0 + Duration::from_secs(10));

        let now = t0 + Duration::from_secs(20);
        map.insert_at(3, "c", now);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get_at(&1, now), None);
        assert_eq!(map.get_at(&2, now), Some(&"b"));
        assert_eq!(map.get_at(&3, now), Some(&"c"));
    }

    #[test]
    fn refreshing_existing_key_when_full_evicts_nothing() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(2, TTL);
        map.insert_at(1, "a", t0);
        map.insert_at(2, "b", t0);
        map.insert_at(1, "a2", t0);

        assert_eq!(map.len(), 2);
        assert_eq!(map.get_at(&2, t0), Some(&"b"));
    }

    #[test]
    fn zero_capacity_stores_nothing() {
        let t0 = Instant::now();
        let mut map = BoundedTimedMap::new(0, TTL);
        assert_eq!(map.insert_at(1, "a", t0), None);
        assert!(map.is_empty());
    }
}
