use std::sync::Arc;

/// Enrichment values for one flow, in the same order as the enrichment
/// engine's output field list. `None` means no match.
///
/// Owned by the encoder loop and refilled for every flow, so nothing is
/// allocated per flow: a hit is an `Arc` refcount bump.
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

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Reset every slot to "no match" before enriching the next flow.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_resets_every_slot_but_keeps_the_width() {
        let mut e = Enriched::new(2);
        e.set(1, "13335");
        assert_eq!(e.get(0), None);
        assert_eq!(e.get(1), Some("13335"));

        e.clear();
        assert_eq!(e.len(), 2);
        assert!(e.iter().all(|v| v.is_none()));
    }
}
