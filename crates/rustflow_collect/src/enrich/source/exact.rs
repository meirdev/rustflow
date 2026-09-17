use std::collections::HashMap;

use super::Source;
use crate::enrich::key::Key;
use crate::enrich::row::Row;

#[derive(Default)]
pub struct ExactTable {
    entries: HashMap<Key, Row>,
}

impl ExactTable {
    pub fn insert(&mut self, key: Key, row: Row) {
        self.entries.insert(key, row);
    }
}

impl Source for ExactTable {
    fn lookup(&self, key: Key) -> Option<Row> {
        self.entries.get(&key).cloned()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}
