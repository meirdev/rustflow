//! Templates of one transport session, shared by NetFlow v9 and IPFIX.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::information_element::DataType;

/// A template as a parser keeps it: with the length and data type of each
/// of its fields, for decoding its records.
pub(crate) struct Entry<T> {
    pub(crate) template: T,
    pub(crate) layout: Box<[Slot]>,
}

#[derive(Clone, Copy)]
pub(crate) struct Slot {
    pub(crate) field_length: u16,
    pub(crate) data_type: DataType,
}

/// Fields one cache may hold across its templates, each template counting as
/// at least one. The exporter decides how many templates it sends and how
/// large they are, so this bounds the memory one exporter can take.
pub(crate) const MAX_FIELDS: usize = 65_536;

/// What a parser keeps of each template, by observation domain (the source
/// ID in NetFlow v9) and template ID. A template expires `timeout` after it
/// was last received, and is dropped at most one more timeout later.
pub(crate) struct TemplateCache<T> {
    timeout: Duration,
    templates: HashMap<(u32, u16), Received<T>>,
    /// Fields of every template held, expired ones included.
    fields: usize,
    next_sweep: Option<Instant>,
    /// The earliest a held template expires: sweeping before then frees
    /// nothing.
    next_expiry: Option<Instant>,
}

struct Received<T> {
    template: T,
    fields: usize,
    at: Instant,
}

impl<T> TemplateCache<Entry<T>> {
    /// Stores a template with the layout of its records; see
    /// [`TemplateCache::insert`].
    pub(crate) fn insert_entry(
        &mut self,
        domain: u32,
        template_id: u16,
        template: T,
        layout: Box<[Slot]>,
    ) {
        let fields = layout.len();
        self.insert(domain, template_id, Entry { template, layout }, fields);
    }
}

impl<T> TemplateCache<T> {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            templates: HashMap::new(),
            fields: 0,
            next_sweep: Instant::now().checked_add(timeout),
            next_expiry: None,
        }
    }

    /// Stores a template of `fields` fields, replacing any earlier one with
    /// its ID right away. One that would take the cache past [`MAX_FIELDS`]
    /// is refused, and the one it replaces is dropped all the same: its data
    /// would otherwise be read by the old layout.
    pub(crate) fn insert(&mut self, domain: u32, template_id: u16, template: T, fields: usize) {
        let now = Instant::now();
        if self.next_sweep.is_some_and(|sweep| now >= sweep) {
            self.remove_expired(now);
        }
        let key = (domain, template_id);
        let fields = fields.max(1);
        if !self.fits(key, fields) && self.next_expiry.is_some_and(|expiry| now >= expiry) {
            self.remove_expired(now);
        }

        let replaced = if self.fits(key, fields) {
            self.fields += fields;
            if let Some(expiry) = now.checked_add(self.timeout) {
                self.next_expiry = Some(self.next_expiry.map_or(expiry, |next| next.min(expiry)));
            }
            let received = Received {
                template,
                fields,
                at: now,
            };
            self.templates.insert(key, received)
        } else {
            self.templates.remove(&key)
        };
        if let Some(replaced) = replaced {
            self.fields -= replaced.fields;
        }
    }

    pub(crate) fn get(&self, domain: u32, template_id: u16) -> Option<&T> {
        self.templates
            .get(&(domain, template_id))
            .filter(|received| received.at.elapsed() < self.timeout)
            .map(|received| &received.template)
    }

    /// Every template of `domain`, expired ones included.
    pub(crate) fn domain_mut(&mut self, domain: u32) -> impl Iterator<Item = &mut T> {
        self.templates
            .iter_mut()
            .filter(move |((template_domain, _), _)| *template_domain == domain)
            .map(|(_, received)| &mut received.template)
    }

    fn fits(&self, key: (u32, u16), fields: usize) -> bool {
        let replaced = self
            .templates
            .get(&key)
            .map_or(0, |received| received.fields);
        self.fields - replaced + fields <= MAX_FIELDS
    }

    fn remove_expired(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.templates
            .retain(|_, received| now.duration_since(received.at) < timeout);
        self.fields = self
            .templates
            .values()
            .map(|received| received.fields)
            .sum();
        self.next_expiry = self
            .templates
            .values()
            .filter_map(|received| received.at.checked_add(timeout))
            .min();
        self.next_sweep = now.checked_add(timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> TemplateCache<&'static str> {
        TemplateCache::new(Duration::from_mins(10))
    }

    #[test]
    fn templates_are_kept_per_domain_and_id() {
        let mut cache = cache();
        cache.insert(7, 256, "a", 1);
        cache.insert(7, 257, "b", 1);
        cache.insert(8, 256, "c", 1);
        assert_eq!(cache.get(7, 256), Some(&"a"));
        assert_eq!(cache.get(7, 257), Some(&"b"));
        assert_eq!(cache.get(8, 256), Some(&"c"));
        assert_eq!(cache.get(8, 257), None);
    }

    #[test]
    fn a_template_sent_again_replaces_the_old_one() {
        let mut cache = cache();
        cache.insert(7, 256, "old", 1);
        cache.insert(7, 256, "new", 1);
        assert_eq!(cache.get(7, 256), Some(&"new"));
    }

    #[test]
    fn expired_templates_are_not_returned() {
        let mut cache = TemplateCache::new(Duration::ZERO);
        cache.insert(7, 256, "a", 1);
        assert_eq!(cache.get(7, 256), None);
    }

    #[test]
    fn templates_past_the_field_budget_are_refused() {
        let mut cache = cache();
        cache.insert(7, 256, "full", MAX_FIELDS);
        cache.insert(7, 257, "over", 1);
        assert_eq!(cache.get(7, 256), Some(&"full"));
        assert_eq!(cache.get(7, 257), None);

        cache.insert(7, 256, "replaced", MAX_FIELDS);
        assert_eq!(cache.get(7, 256), Some(&"replaced"));
    }

    #[test]
    fn a_refused_template_drops_the_one_it_replaces() {
        let mut cache = cache();
        cache.insert(7, 256, "old", 1);
        cache.insert(7, 257, "rest", MAX_FIELDS - 1);
        cache.insert(7, 256, "new", 2);
        assert_eq!(cache.get(7, 256), None);
        assert_eq!(cache.fields, MAX_FIELDS - 1);
    }

    #[test]
    fn templates_without_fields_count_as_one() {
        let mut cache = cache();
        for template_id in 0..=u16::MAX {
            cache.insert(7, template_id, "empty", 0);
        }
        cache.insert(8, 256, "over", 0);
        assert_eq!(cache.get(7, u16::MAX), Some(&"empty"));
        assert_eq!(cache.get(8, 256), None);
    }

    #[test]
    fn expired_templates_are_swept_and_free_their_fields() {
        let mut cache = TemplateCache::new(Duration::ZERO);
        cache.insert(7, 256, "full", MAX_FIELDS);
        cache.insert(7, 257, "next", 1);
        assert_eq!(cache.templates.len(), 1);
        assert_eq!(cache.fields, 1);
    }

    #[test]
    fn domain_mut_reaches_only_that_domain() {
        let mut cache = cache();
        cache.insert(7, 256, "a", 1);
        cache.insert(7, 257, "b", 1);
        cache.insert(8, 256, "c", 1);
        for template in cache.domain_mut(7) {
            *template = "changed";
        }
        assert_eq!(cache.get(7, 256), Some(&"changed"));
        assert_eq!(cache.get(7, 257), Some(&"changed"));
        assert_eq!(cache.get(8, 256), Some(&"c"));
    }
}
