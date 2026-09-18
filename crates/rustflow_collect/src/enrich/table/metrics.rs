use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SourceLabel {
    pub source: String,
}

#[derive(Clone, Default)]
pub struct TableMetrics {
    pub loaded_rows: Family<SourceLabel, Gauge>,
    pub last_load_timestamp_seconds: Family<SourceLabel, Gauge>,
    pub loads_total: Family<SourceLabel, Counter>,
    pub reload_failures_total: Family<SourceLabel, Counter>,
    pub watcher_failures_total: Family<SourceLabel, Counter>,
}

impl TableMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "enrichment_loaded_rows",
            "Number of rows currently loaded from an enrichment source",
            self.loaded_rows.clone(),
        );
        registry.register(
            "enrichment_last_reload_timestamp_seconds",
            "Unix timestamp of the latest successful enrichment load",
            self.last_load_timestamp_seconds.clone(),
        );
        registry.register(
            "enrichment_loads",
            "Number of successful enrichment loads",
            self.loads_total.clone(),
        );
        registry.register(
            "enrichment_reload_failures",
            "Number of failed enrichment reloads",
            self.reload_failures_total.clone(),
        );
        registry.register(
            "enrichment_watcher_failures",
            "Number of file watcher errors on an enrichment source",
            self.watcher_failures_total.clone(),
        );
    }

    pub fn for_source(&self, source: &str) -> SourceMetrics {
        let label = SourceLabel {
            source: source.to_string(),
        };
        SourceMetrics {
            loaded_rows: self.loaded_rows.get_or_create_owned(&label),
            last_load_timestamp_seconds: self
                .last_load_timestamp_seconds
                .get_or_create_owned(&label),
            loads_total: self.loads_total.get_or_create_owned(&label),
            reload_failures_total: self.reload_failures_total.get_or_create_owned(&label),
            watcher_failures_total: self.watcher_failures_total.get_or_create_owned(&label),
        }
    }
}

pub struct SourceMetrics {
    pub loaded_rows: Gauge,
    pub last_load_timestamp_seconds: Gauge,
    pub loads_total: Counter,
    pub reload_failures_total: Counter,
    pub watcher_failures_total: Counter,
}
