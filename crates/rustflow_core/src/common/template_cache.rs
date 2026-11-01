use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, warn};
use rustc_hash::FxHashMap;

/// Fields one cache may hold across all its templates. The exporter decides
/// how many templates it sends and how large they are, so this is what bounds
/// the memory one exporter can take.
pub const MAX_TEMPLATE_FIELDS: usize = 65_536;

/// A template's observation domain (the source ID in NetFlow v9) and ID.
pub type TemplateKey = (u32, u16);

/// The templates of one exporter, by observation domain. A template expires
/// `timeout` after it was last sent, and is dropped at most one more timeout
/// later.
pub struct TemplateCache<F> {
    domains: FxHashMap<u32, FxHashMap<u16, Entry<F>>>,
    timeout: Duration,
    /// Fields of every entry, expired ones included.
    fields: usize,
    next_sweep: Instant,
    /// The earliest an entry can expire: a sweep before then frees nothing.
    next_expiry: Option<Instant>,
    /// A template was refused since the last new one was stored; further
    /// refusals are not worth a warning each.
    refusing: bool,
}

struct Entry<F> {
    fields: Arc<[F]>,
    sent_at: Instant,
}

impl<F> TemplateCache<F> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            domains: FxHashMap::default(),
            timeout,
            fields: 0,
            next_sweep: Instant::now() + timeout,
            next_expiry: None,
            refusing: false,
        }
    }

    pub fn get(&self, &(domain, id): &TemplateKey) -> Option<&Arc<[F]>> {
        self.domains
            .get(&domain)?
            .get(&id)
            .filter(|entry| entry.sent_at.elapsed() < self.timeout)
            .map(|entry| &entry.fields)
    }

    pub fn contains_key(&self, key: &TemplateKey) -> bool {
        self.get(key).is_some()
    }

    /// Stores or refreshes a template, unless that would take the cache past
    /// [`MAX_TEMPLATE_FIELDS`]. Other templates are never pushed out, but one
    /// the exporter has just redefined is dropped: its data would otherwise
    /// be read with the old layout.
    pub fn insert(&mut self, key: TemplateKey, fields: Arc<[F]>) {
        let now = Instant::now();
        if now >= self.next_sweep {
            self.remove_expired(now);
        }
        if !self.fits(key, &fields) {
            if self.next_expiry.is_some_and(|expiry| now >= expiry) {
                self.remove_expired(now);
            }
            if !self.fits(key, &fields) {
                self.refuse(key);
                return;
            }
        }

        let (domain, id) = key;
        self.fields += fields.len();
        let entry = Entry {
            fields,
            sent_at: now,
        };
        match self.domains.entry(domain).or_default().insert(id, entry) {
            Some(replaced) => self.fields -= replaced.fields.len(),
            None => self.refusing = false,
        }
        let expiry = now + self.timeout;
        self.next_expiry = Some(self.next_expiry.map_or(expiry, |next| next.min(expiry)));
    }

    fn refuse(&mut self, key: TemplateKey) {
        if self.refusing {
            debug!("Template {key:?} not stored: the exporter's templates are at the field budget");
        } else {
            warn!(
                "Template {key:?} not stored, and any earlier one dropped: the exporter's templates would exceed {MAX_TEMPLATE_FIELDS} fields"
            );
            self.refusing = true;
        }
        self.remove(&key);
    }

    pub fn remove(&mut self, &(domain, id): &TemplateKey) {
        let Some(templates) = self.domains.get_mut(&domain) else {
            return;
        };
        if let Some(entry) = templates.remove(&id) {
            self.fields -= entry.fields.len();
        }
        if templates.is_empty() {
            self.domains.remove(&domain);
        }
    }

    /// Withdraws every template of `domain`.
    pub fn remove_domain(&mut self, domain: u32) {
        if let Some(templates) = self.domains.remove(&domain) {
            self.fields -= templates
                .values()
                .map(|entry| entry.fields.len())
                .sum::<usize>();
        }
    }

    pub fn len(&self) -> usize {
        self.domains.values().map(FxHashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    fn fits(&self, (domain, id): TemplateKey, fields: &[F]) -> bool {
        let replaced = self
            .domains
            .get(&domain)
            .and_then(|templates| templates.get(&id))
            .map_or(0, |entry| entry.fields.len());
        self.fields - replaced + fields.len() <= MAX_TEMPLATE_FIELDS
    }

    fn remove_expired(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.domains.retain(|_, templates| {
            templates.retain(|_, entry| now.duration_since(entry.sent_at) < timeout);
            !templates.is_empty()
        });
        let entries = || self.domains.values().flat_map(FxHashMap::values);
        self.fields = entries().map(|entry| entry.fields.len()).sum();
        self.next_expiry = entries().map(|entry| entry.sent_at + timeout).min();
        self.next_sweep = now + timeout;
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
        cache.insert((0, 1), fields(MAX_TEMPLATE_FIELDS - 10));
        cache.insert((0, 2), fields(10));
        cache.insert((0, 3), fields(1));
        assert!(cache.contains_key(&(0, 1)));
        assert!(cache.contains_key(&(0, 2)));
        assert!(!cache.contains_key(&(0, 3)));

        // A refresh replaces what it refreshes, so it still fits.
        cache.insert((0, 1), fields(MAX_TEMPLATE_FIELDS - 10));
        assert!(cache.contains_key(&(0, 1)));

        cache.remove(&(0, 2));
        cache.insert((0, 3), fields(10));
        assert!(cache.contains_key(&(0, 3)));
    }

    #[test]
    fn a_redefinition_past_the_budget_drops_the_old_template() {
        let mut cache = TemplateCache::new(Duration::from_mins(10));
        cache.insert((0, 1), fields(MAX_TEMPLATE_FIELDS - 10));
        cache.insert((0, 2), fields(10));

        cache.insert((0, 2), fields(11));
        assert!(cache.contains_key(&(0, 1)));
        assert!(!cache.contains_key(&(0, 2)));

        // Dropping it freed its share of the budget.
        cache.insert((0, 3), fields(10));
        assert!(cache.contains_key(&(0, 3)));
    }

    #[test]
    fn withdrawing_a_domain_frees_only_its_templates() {
        let mut cache = TemplateCache::new(Duration::from_mins(10));
        cache.insert((1, 256), fields(10));
        cache.insert((1, 257), fields(10));
        cache.insert((2, 256), fields(MAX_TEMPLATE_FIELDS - 20));

        cache.remove_domain(1);
        assert!(!cache.contains_key(&(1, 256)));
        assert!(!cache.contains_key(&(1, 257)));
        assert!(cache.contains_key(&(2, 256)));

        cache.insert((3, 256), fields(20));
        assert!(cache.contains_key(&(3, 256)));
    }

    #[test]
    fn expired_templates_are_dropped_and_free_their_budget() {
        let mut cache = TemplateCache::new(Duration::ZERO);
        cache.insert((0, 1), fields(MAX_TEMPLATE_FIELDS));
        assert!(!cache.contains_key(&(0, 1)));

        cache.insert((0, 2), fields(MAX_TEMPLATE_FIELDS));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.domains[&0].keys().collect::<Vec<_>>(), [&2]);
    }
}
