use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

#[derive(Clone)]
pub struct TableMetrics {
    pub loaded_rows: IntGaugeVec,
    pub last_load_timestamp_seconds: IntGaugeVec,
    pub loads_total: IntCounterVec,
    pub reload_failures_total: IntCounterVec,
    pub watcher_failures_total: IntCounterVec,
}

impl TableMetrics {
    pub fn new() -> Self {
        let gauge = |name, help| IntGaugeVec::new(Opts::new(name, help), &["source"]).unwrap();
        let counter = |name, help| IntCounterVec::new(Opts::new(name, help), &["source"]).unwrap();
        Self {
            loaded_rows: gauge(
                "enrichment_loaded_rows",
                "Number of rows currently loaded from an enrichment source",
            ),
            last_load_timestamp_seconds: gauge(
                "enrichment_last_reload_timestamp_seconds",
                "Unix timestamp of the latest successful enrichment load",
            ),
            loads_total: counter(
                "enrichment_loads_total",
                "Number of successful enrichment loads",
            ),
            reload_failures_total: counter(
                "enrichment_reload_failures_total",
                "Number of failed enrichment reloads",
            ),
            watcher_failures_total: counter(
                "enrichment_watcher_failures_total",
                "Number of file watcher errors on an enrichment source",
            ),
        }
    }

    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        registry.register(Box::new(self.loaded_rows.clone()))?;
        registry.register(Box::new(self.last_load_timestamp_seconds.clone()))?;
        registry.register(Box::new(self.loads_total.clone()))?;
        registry.register(Box::new(self.reload_failures_total.clone()))?;
        registry.register(Box::new(self.watcher_failures_total.clone()))
    }

    pub fn for_source(&self, source: &str) -> SourceMetrics {
        let label = [source];
        SourceMetrics {
            loaded_rows: self.loaded_rows.with_label_values(&label),
            last_load_timestamp_seconds: self.last_load_timestamp_seconds.with_label_values(&label),
            loads_total: self.loads_total.with_label_values(&label),
            reload_failures_total: self.reload_failures_total.with_label_values(&label),
            watcher_failures_total: self.watcher_failures_total.with_label_values(&label),
        }
    }
}

impl Default for TableMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SourceMetrics {
    pub loaded_rows: IntGauge,
    pub last_load_timestamp_seconds: IntGauge,
    pub loads_total: IntCounter,
    pub reload_failures_total: IntCounter,
    pub watcher_failures_total: IntCounter,
}
