use std::time::SystemTime;

use rustflow_convert::Record;

use crate::Item;

/// Takes items, emits items: a filter emits an item or not, an enrichment
/// emits it with more elements, an aggregation keeps items and emits their
/// sum on a tick.
///
/// A process never calls what comes after it; it pushes into an
/// [`Output`] the pipeline hands on, so what it emits depends on its input
/// and its own state alone.
pub trait Process: Send {
    fn item(&mut self, item: Item, out: &mut Output);

    /// Time has passed: a window may have closed, a cache may have
    /// expired.
    fn tick(&mut self, _now: SystemTime, _out: &mut Output) {}

    /// The stream is ending; emit whatever is held.
    fn finish(&mut self, _out: &mut Output) {}
}

/// Where a process puts what it emits.
#[derive(Debug, Default)]
pub struct Output {
    items: Vec<Item>,
}

impl Output {
    pub fn push(&mut self, item: Item) {
        self.items.push(item);
    }

    pub fn record(&mut self, record: Record) {
        self.items.push(Item::Record(record));
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn into_items(self) -> Vec<Item> {
        self.items
    }
}
