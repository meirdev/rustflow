use std::sync::Arc;

use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, LookupKey};
use crate::enrich::table::Table;
use crate::enrich::table::metrics::TableMetrics;
use crate::enrich::{Result, Row, Source};

pub type Enriched = Vec<Option<Arc<str>>>;

struct Lookup {
    table: Table,
    groups: Vec<Group>,
}

struct Group {
    key: LookupKey,
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
            match groups.iter_mut().find(|g| g.key == mapping.key) {
                Some(group) => group.fields.push(field),
                None => groups.push(Group {
                    key: mapping.key,
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
                let row: Option<Row> = group.key.extract(flow).and_then(|key| source.lookup(key));
                let Some(row) = row else {
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
