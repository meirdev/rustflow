use std::collections::HashMap;

use toml::Table;

use crate::{Error, Exporter, Meter, Process};

/// What a component's options build into, or why they could not.
pub type Built<T> = Result<Box<T>, Box<dyn std::error::Error + Send + Sync>>;

type Factory<T> = Box<dyn Fn(&Table) -> Built<T> + Send + Sync>;

/// The meter, process and exporter types a configuration may name, each
/// with the constructor that builds one from its options.
#[derive(Default)]
pub struct Registry {
    meters: HashMap<String, Factory<dyn Meter>>,
    processes: HashMap<String, Factory<dyn Process>>,
    exporters: HashMap<String, Factory<dyn Exporter>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a meter type, replacing any of the same name.
    pub fn meter(
        mut self,
        kind: impl Into<String>,
        build: impl Fn(&Table) -> Built<dyn Meter> + Send + Sync + 'static,
    ) -> Self {
        self.meters.insert(kind.into(), Box::new(build));
        self
    }

    /// Adds a process type, replacing any of the same name.
    pub fn process(
        mut self,
        kind: impl Into<String>,
        build: impl Fn(&Table) -> Built<dyn Process> + Send + Sync + 'static,
    ) -> Self {
        self.processes.insert(kind.into(), Box::new(build));
        self
    }

    /// Adds an exporter type, replacing any of the same name.
    pub fn exporter(
        mut self,
        kind: impl Into<String>,
        build: impl Fn(&Table) -> Built<dyn Exporter> + Send + Sync + 'static,
    ) -> Self {
        self.exporters.insert(kind.into(), Box::new(build));
        self
    }

    pub(crate) fn build_meter(
        &self,
        name: &str,
        kind: &str,
        options: &Table,
    ) -> Result<Box<dyn Meter>, Error> {
        let build = self
            .meters
            .get(kind)
            .ok_or_else(|| Error::UnknownMeter(kind.to_owned()))?;
        build(options).map_err(|source| Error::Component {
            name: name.to_owned(),
            source,
        })
    }

    pub(crate) fn build_process(
        &self,
        name: &str,
        kind: &str,
        options: &Table,
    ) -> Result<Box<dyn Process>, Error> {
        let build = self
            .processes
            .get(kind)
            .ok_or_else(|| Error::UnknownProcess(kind.to_owned()))?;
        build(options).map_err(|source| Error::Component {
            name: name.to_owned(),
            source,
        })
    }

    pub(crate) fn build_exporter(
        &self,
        name: &str,
        kind: &str,
        options: &Table,
    ) -> Result<Box<dyn Exporter>, Error> {
        let build = self
            .exporters
            .get(kind)
            .ok_or_else(|| Error::UnknownExporter(kind.to_owned()))?;
        build(options).map_err(|source| Error::Component {
            name: name.to_owned(),
            source,
        })
    }
}
