use std::sync::Arc;

use arrayvec::ArrayVec;
use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, LookupKey, MAX_KEYS};
use crate::enrich::table::Table;
use crate::enrich::table::metrics::TableMetrics;
use crate::enrich::{Key, Result, Source};

pub type Enriched = Vec<Option<Arc<str>>>;

struct Lookup {
    table: Table,
    groups: Vec<Group>,
}

struct Group {
    keys: Vec<LookupKey>,
    /// Source column to output field index.
    fields: Vec<(usize, usize)>,
}

pub struct EnrichmentEngine {
    lookups: Vec<Lookup>,
    output_fields: Vec<String>,
    metrics: TableMetrics,
}

impl EnrichmentEngine {
    pub fn new(metrics: TableMetrics) -> Self {
        Self {
            lookups: Vec::new(),
            output_fields: Vec::new(),
            metrics,
        }
    }

    pub fn add(&mut self, config: EnrichmentConfig) -> Result<usize> {
        let columns = config.source.columns();
        let mut groups: Vec<Group> = Vec::new();
        for mapping in &config.mappings {
            let output = match self
                .output_fields
                .iter()
                .position(|f| *f == mapping.output_field)
            {
                Some(index) => index,
                None => {
                    self.output_fields.push(mapping.output_field.clone());
                    self.output_fields.len() - 1
                }
            };
            let column = columns
                .iter()
                .position(|c| *c == mapping.source_column)
                .expect("mapping columns are the source columns");
            let field = (column, output);
            match groups.iter_mut().find(|g| g.keys == mapping.keys) {
                Some(group) => group.fields.push(field),
                None => groups.push(Group {
                    keys: mapping.keys.clone(),
                    fields: vec![field],
                }),
            }
        }
        let table = Table::new(config.source, &self.metrics)?;
        let loaded = table.len();
        self.lookups.push(Lookup { table, groups });
        Ok(loaded)
    }

    pub fn output_fields(&self) -> &[String] {
        &self.output_fields
    }

    /// Pins the current version of every table. Taking one per chunk
    /// keeps the per-flow path free of locks; a reload shows up on the
    /// next chunk.
    pub fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            engine: self,
            sources: self.lookups.iter().map(|l| l.table.snapshot()).collect(),
        }
    }
}

/// The tables as they were when the snapshot was taken.
pub struct Snapshot<'a> {
    engine: &'a EnrichmentEngine,
    sources: Vec<Arc<dyn Source>>,
}

impl Snapshot<'_> {
    pub fn enrich(&self, flow: &CommonFlow, out: &mut Enriched) {
        out.fill(None);
        for (lookup, source) in self.engine.lookups.iter().zip(&self.sources) {
            for group in &lookup.groups {
                // Every key field must be present for the group to match.
                let keys: Option<ArrayVec<Key, MAX_KEYS>> =
                    group.keys.iter().map(|key| key.extract(flow)).collect();
                let Some(row) = keys.and_then(|keys| source.lookup(&keys)) else {
                    continue;
                };
                for &(column, output) in &group.fields {
                    if let Some(value) = &row.values()[column] {
                        out[output] = Some(Arc::clone(value));
                    }
                }
            }
        }
    }
}
