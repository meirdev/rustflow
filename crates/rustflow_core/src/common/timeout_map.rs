use std::borrow::Borrow;
use std::hash::Hash;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

#[derive(Debug)]
pub struct TimeoutHashMap<K, V> {
    map: FxHashMap<K, TimedEntry<V>>,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct TimedEntry<V> {
    value: V,
    inserted_at: Instant,
}

impl<K, V> TimeoutHashMap<K, V>
where
    K: Eq + Hash,
{
    pub fn new(timeout: Duration) -> Self {
        Self {
            map: FxHashMap::default(),
            timeout,
        }
    }

    pub fn with_capacity(timeout: Duration, capacity: usize) -> Self {
        Self {
            map: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            timeout,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let entry = TimedEntry {
            value,
            inserted_at: Instant::now(),
        };

        self.map.insert(key, entry).and_then(|old| {
            if old.inserted_at.elapsed() < self.timeout {
                Some(old.value)
            } else {
                None
            }
        })
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.timeout {
                Some(&entry.value)
            } else {
                None
            }
        })
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let timeout = self.timeout;

        self.map.get_mut(key).and_then(|entry| {
            if entry.inserted_at.elapsed() < timeout {
                Some(&mut entry.value)
            } else {
                None
            }
        })
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(key).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.timeout {
                Some(entry.value)
            } else {
                None
            }
        })
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn cleanup(&mut self) {
        let timeout = self.timeout;

        self.map
            .retain(|_, entry| entry.inserted_at.elapsed() < timeout);
    }

    pub fn count_valid(&self) -> usize {
        self.map
            .values()
            .filter(|entry| entry.inserted_at.elapsed() < self.timeout)
            .count()
    }

    pub fn refresh<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(entry) = self.map.get_mut(key) {
            if entry.inserted_at.elapsed() < self.timeout {
                entry.inserted_at = Instant::now();
                return true;
            }
        }
        false
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let timeout = self.timeout;

        self.map.iter().filter_map(move |(k, entry)| {
            if entry.inserted_at.elapsed() < timeout {
                Some((k, &entry.value))
            } else {
                None
            }
        })
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }
}

impl<K, V> Default for TimeoutHashMap<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new(Duration::from_secs(30 * 60))
    }
}

impl<K, V: Clone> Clone for TimeoutHashMap<K, V>
where
    K: Eq + Hash + Clone,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            timeout: self.timeout,
        }
    }
}
