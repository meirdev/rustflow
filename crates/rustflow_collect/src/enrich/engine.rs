use std::collections::HashMap;

use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, LookupKey};
use crate::enrich::table::Table;
use crate::enrich::table::metrics::TableMetrics;
use crate::enrich::{Result, Row};

struct Lookup {
    table: Table,
    groups: Vec<Group>,
}

struct Group {
    key: LookupKey,
    fields: Vec<(usize, String)>,
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
            if !self.output_fields.contains(&mapping.output_field) {
                self.output_fields.push(mapping.output_field.clone());
            }
            let column = columns
                .iter()
                .position(|c| *c == mapping.source_column)
                .expect("mapping columns are the source columns");
            let field = (column, mapping.output_field.clone());
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

    pub fn enrich(&self, flow: &CommonFlow) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for lookup in &self.lookups {
            let snapshot = lookup.table.snapshot();
            for group in &lookup.groups {
                let row: Option<Row> = group.key.extract(flow).and_then(|key| snapshot.lookup(key));
                let Some(row) = row else {
                    continue;
                };
                let values: &[Option<String>] = row.values();
                for (column, output) in &group.fields {
                    if let Some(value) = &values[*column] {
                        result.insert(output.clone(), value.clone());
                    }
                }
            }
        }
        result
    }
}
