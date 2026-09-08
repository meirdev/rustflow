use std::collections::hash_map::RandomState;

use hashbrown::{Equivalent, HashMap};

use super::{Key, Lookup, Row};

#[derive(Default)]
pub struct ExactTable {
    entries: HashMap<Key<'static>, Row, RandomState>,
}

impl ExactTable {
    pub fn insert(&mut self, key: Key<'_>, row: Row) {
        self.entries.insert(key.into_owned(), row);
    }
}

impl Lookup for ExactTable {
    fn lookup(&self, key: Key<'_>) -> Option<&Row> {
        self.entries.get(&KeyRef(&key))
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// Compare a borrowed probe with an owned key without tying the returned row's
// lifetime to the probe. The wrapper hashes exactly like its inner Key.
#[derive(Hash)]
struct KeyRef<'a, 'b>(&'a Key<'b>);

impl Equivalent<Key<'static>> for KeyRef<'_, '_> {
    fn equivalent(&self, stored: &Key<'static>) -> bool {
        self.0 == stored
    }
}
