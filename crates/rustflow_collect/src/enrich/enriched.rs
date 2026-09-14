use std::sync::Arc;

/// Enrichment values for one flow, in the order of the engine's output
/// field list. Refilled per flow; a hit is an `Arc` refcount bump.
#[derive(Clone, Debug, Default)]
pub struct Enriched {
    values: Vec<Option<Arc<str>>>,
}

impl Enriched {
    pub fn new(field_count: usize) -> Self {
        Self {
            values: vec![None; field_count],
        }
    }

    pub fn clear(&mut self) {
        self.values.iter_mut().for_each(|v| *v = None);
    }

    pub fn set(&mut self, index: usize, value: impl Into<Arc<str>>) {
        self.values[index] = Some(value.into());
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        self.values[index].as_deref()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Option<&str>> + '_ {
        self.values.iter().map(|v| v.as_deref())
    }
}
