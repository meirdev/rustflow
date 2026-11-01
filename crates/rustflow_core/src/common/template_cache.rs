use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::warn;
use rustc_hash::FxHashMap;

/// Fields one cache may hold across all its templates. The exporter decides
/// how many templates it sends and how large they are, so this is what bounds
/// the memory one exporter can take.
pub const MAX_TEMPLATE_FIELDS: usize = 65_536;

/// The templates of one exporter. A template expires `timeout` after it was
/// last sent, and is dropped at most one more timeout later.
pub struct TemplateCache<K, F> {
    entries: FxHashMap<K, Entry<F>>,
    timeout: Duration,
    /// Fields of every entry, expired ones included.
    fields: usize,
    next_sweep: Instant,
}

struct Entry<F> {
    fields: Arc<[F]>,
    sent_at: Instant,
}

impl<K: Eq + Hash + Debug, F> TemplateCache<K, F> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            entries: FxHashMap::default(),
            timeout,
            fields: 0,
            next_sweep: Instant::now() + timeout,
        }
    }

    pub fn get(&self, key: &K) -> Option<&Arc<[F]>> {
        self.entries
            .get(key)
            .filter(|entry| entry.sent_at.elapsed() < self.timeout)
            .map(|entry| &entry.fields)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Stores or refreshes a template, unless that would take the cache past
    /// [`MAX_TEMPLATE_FIELDS`]; a template already stored is never pushed out.
    pub fn insert(&mut self, key: K, fields: Arc<[F]>) {
        let now = Instant::now();
        if now >= self.next_sweep || !self.fits(&key, &fields) {
            self.remove_expired(now);
            if !self.fits(&key, &fields) {
                warn!(
                    "Template {key:?} not stored: the exporter's templates would exceed {MAX_TEMPLATE_FIELDS} fields"
                );
                return;
            }
        }
        self.fields += fields.len();
        if let Some(replaced) = self.entries.insert(
            key,
            Entry {
                fields,
                sent_at: now,
            },
        ) {
            self.fields -= replaced.fields.len();
        }
    }

    pub fn remove(&mut self, key: &K) {
        if let Some(entry) = self.entries.remove(key) {
            self.fields -= entry.fields.len();
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        self.entries.retain(|key, _| keep(key));
        self.recount();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn fits(&self, key: &K, fields: &[F]) -> bool {
        let replaced = self.entries.get(key).map_or(0, |entry| entry.fields.len());
        self.fields - replaced + fields.len() <= MAX_TEMPLATE_FIELDS
    }

    fn remove_expired(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.entries
            .retain(|_, entry| now.duration_since(entry.sent_at) < timeout);
        self.recount();
        self.next_sweep = now + timeout;
    }

    fn recount(&mut self) {
        self.fields = self.entries.values().map(|entry| entry.fields.len()).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(count: usize) -> Arc<[()]> {
        vec![(); count].into()
    }

    #[test]
    fn templates_past_the_field_budget_are_not_stored() {
        let mut cache = TemplateCache::new(Duration::from_mins(10));
        cache.insert(1, fields(MAX_TEMPLATE_FIELDS - 10));
        cache.insert(2, fields(10));
        cache.insert(3, fields(1));
        assert!(cache.contains_key(&1));
        assert!(cache.contains_key(&2));
        assert!(!cache.contains_key(&3));

        // A refresh replaces what it refreshes, so it still fits.
        cache.insert(1, fields(MAX_TEMPLATE_FIELDS - 10));
        assert!(cache.contains_key(&1));

        cache.remove(&2);
        cache.insert(3, fields(10));
        assert!(cache.contains_key(&3));
    }

    #[test]
    fn expired_templates_are_dropped_and_free_their_budget() {
        let mut cache = TemplateCache::new(Duration::ZERO);
        cache.insert(1, fields(MAX_TEMPLATE_FIELDS));
        assert!(!cache.contains_key(&1));

        cache.insert(2, fields(MAX_TEMPLATE_FIELDS));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.entries.keys().collect::<Vec<_>>(), [&2]);
    }
}
