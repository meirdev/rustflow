//! Flow-level enrichment: every configured source is a reloadable [`Table`],
//! and each flow is looked up once per distinct key field and mapped to the
//! configured output fields.
use std::collections::HashMap;
use std::sync::Arc;

use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{IntCounterVec, IntGaugeVec, Opts};
use rustflow_core::common::common_flow::CommonFlow;

use crate::enrich::config::{EnrichmentConfig, LookupKey};
use crate::enrich::table::Table;
use crate::enrich::{Result, Row};

/// One source and the fields it produces, grouped by the flow field to look
/// up so each key is resolved once per flow.
struct Lookup {
    table: Arc<Table>,
    groups: Vec<Group>,
}

struct Group {
    key: LookupKey,
    /// Column position in the row and the output field it feeds.
    fields: Vec<(usize, String)>,
}

#[derive(Default)]
pub struct EnrichmentEngine {
    lookups: Vec<Lookup>,
    output_fields: Vec<String>,
}

impl EnrichmentEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the source and register its fields. Returns the number of rows
    /// loaded.
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
        let table = Table::new(config.source)?;
        let loaded = table.stats().loaded_rows;
        self.lookups.push(Lookup {
            table: Arc::new(table),
            groups,
        });
        Ok(loaded)
    }

    /// Every output field, in configuration order.
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

    /// A Prometheus collector that reports every table's load statistics.
    pub fn collector(&self) -> TableMetrics {
        TableMetrics::new(
            self.lookups
                .iter()
                .map(|lookup| Arc::clone(&lookup.table))
                .collect(),
        )
    }
}

/// Reads each table's [`LoadStats`](crate::enrich::LoadStats) at scrape
/// time, labeled by source path.
pub struct TableMetrics {
    tables: Vec<Arc<Table>>,
    descs: Vec<Desc>,
}

impl TableMetrics {
    fn new(tables: Vec<Arc<Table>>) -> Self {
        let descs = Self::families()
            .iter()
            .into_iter()
            .flat_map(|family| family.desc().into_iter().cloned())
            .collect();
        Self { tables, descs }
    }

    fn families() -> Families {
        let gauge = |name, help| IntGaugeVec::new(Opts::new(name, help), &["source"]).unwrap();
        let counter = |name, help| IntCounterVec::new(Opts::new(name, help), &["source"]).unwrap();
        Families {
            loaded_rows: gauge(
                "enrichment_loaded_rows",
                "Number of rows currently loaded from an enrichment source",
            ),
            last_load: gauge(
                "enrichment_last_reload_timestamp_seconds",
                "Unix timestamp of the latest successful enrichment load",
            ),
            loads: counter(
                "enrichment_loads_total",
                "Number of successful enrichment loads",
            ),
            failures: counter(
                "enrichment_reload_failures_total",
                "Number of failed enrichment reloads",
            ),
            watcher_failures: counter(
                "enrichment_watcher_failures_total",
                "Number of file watcher errors on an enrichment source",
            ),
        }
    }
}

struct Families {
    loaded_rows: IntGaugeVec,
    last_load: IntGaugeVec,
    loads: IntCounterVec,
    failures: IntCounterVec,
    watcher_failures: IntCounterVec,
}

impl Families {
    fn iter(&self) -> [&dyn Collector; 5] {
        [
            &self.loaded_rows,
            &self.last_load,
            &self.loads,
            &self.failures,
            &self.watcher_failures,
        ]
    }
}

impl Collector for TableMetrics {
    fn desc(&self) -> Vec<&Desc> {
        self.descs.iter().collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let families = Self::families();
        for table in &self.tables {
            let stats = table.stats();
            let source = table.config().source().display().to_string();
            let label = [source.as_str()];
            families
                .loaded_rows
                .with_label_values(&label)
                .set(stats.loaded_rows as i64);
            let last = stats
                .last_success
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs() as i64);
            families.last_load.with_label_values(&label).set(last);
            families
                .loads
                .with_label_values(&label)
                .inc_by(stats.successful_loads);
            families
                .failures
                .with_label_values(&label)
                .inc_by(stats.reload_failures);
            families
                .watcher_failures
                .with_label_values(&label)
                .inc_by(stats.watcher_failures);
        }
        families
            .iter()
            .into_iter()
            .flat_map(Collector::collect)
            .collect()
    }
}
