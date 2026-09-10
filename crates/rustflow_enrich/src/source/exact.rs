use std::collections::hash_map::RandomState;

use hashbrown::{Equivalent, HashMap};

use super::Source;
use crate::key::Key;
use crate::row::Row;

#[derive(Default)]
pub struct ExactTable {
    entries: HashMap<Key<'static>, Row, RandomState>,
}

impl ExactTable {
    pub fn insert(&mut self, key: Key<'static>, row: Row) {
        self.entries.insert(key, row);
    }
}

impl Source for ExactTable {
    fn lookup(&self, key: Key<'_>) -> Option<Row> {
        self.entries.get(&KeyRef(&key)).cloned()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Hash)]
struct KeyRef<'a, 'b>(&'a Key<'b>);

impl Equivalent<Key<'static>> for KeyRef<'_, '_> {
    fn equivalent(&self, stored: &Key<'static>) -> bool {
        self.0 == stored
    }
}
