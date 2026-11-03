use std::collections::BTreeMap;

use serde::Deserialize;
use toml::Table;

use crate::{Error, Pipeline, Registry};

/// A pipeline as a configuration file describes it: collectors, processes
/// and exporters by name, each of a type, processes and exporters fed by
/// the components their inputs name.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub collectors: BTreeMap<String, Collector>,
    #[serde(default)]
    pub processes: BTreeMap<String, Component>,
    #[serde(default)]
    pub exporters: BTreeMap<String, Component>,
}

/// A Collecting Process: its type, and the options its type reads, such
/// as where to listen. The embedding program runs it, since what a
/// collector listens to is its business; the pipeline only knows its
/// name.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Collector {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub options: Table,
}

/// A process or an exporter: its type, what feeds it, and the options its
/// type reads.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(flatten)]
    pub options: Table,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, Error> {
        toml::from_str(text).map_err(Error::Parse)
    }

    /// Builds the pipeline, every process and exporter by its type's
    /// constructor in `registry`. The collectors are named, for the
    /// embedding program to feed; see [`Pipeline::collector`].
    pub fn build(&self, registry: &Registry) -> Result<Pipeline, Error> {
        if self.collectors.is_empty() {
            return Err(Error::NoCollectors);
        }
        let mut builder = Pipeline::builder(self.collectors.keys().cloned());
        for (name, component) in &self.processes {
            let process = registry.build_process(name, &component.kind, &component.options)?;
            builder = builder.process(name, &component.inputs, process);
        }
        for (name, component) in &self.exporters {
            let exporter = registry.build_exporter(name, &component.kind, &component.options)?;
            builder = builder.exporter(name, &component.inputs, exporter);
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Item;
    use crate::pipeline::tests::{Collect, Select, Shared, record};

    const CONFIG: &str = r#"
        [collectors.flows]
        type = "netflow"
        listen = ":9995"

        [processes.tcp]
        type = "select"
        inputs = ["flows"]
        protocol = 6

        [exporters.everything]
        type = "collect"
        inputs = ["flows"]

        [exporters.tcp_only]
        type = "collect"
        inputs = ["tcp"]
    "#;

    fn registry(out: &Shared) -> Registry {
        let out = Arc::clone(out);
        Registry::new()
            .process("select", |options| {
                let protocol = options
                    .get("protocol")
                    .and_then(toml::Value::as_integer)
                    .ok_or("select needs a protocol number")?;
                Ok(Box::new(Select(u8::try_from(protocol)?)))
            })
            .exporter("collect", move |_| Ok(Box::new(Collect(Arc::clone(&out)))))
    }

    #[test]
    fn a_configuration_builds_the_pipeline_it_describes() {
        let config = Config::parse(CONFIG).unwrap();
        let flows = &config.collectors["flows"];
        assert_eq!(flows.kind, "netflow");
        assert_eq!(
            flows.options.get("listen"),
            Some(&toml::Value::String(":9995".into()))
        );
        let tcp = &config.processes["tcp"];
        assert_eq!(tcp.kind, "select");
        assert_eq!(tcp.inputs, ["flows"]);
        assert_eq!(tcp.options.get("protocol"), Some(&toml::Value::Integer(6)));
        assert_eq!(config.exporters.len(), 2);

        let out = Shared::default();
        let mut pipeline = config.build(&registry(&out)).unwrap();
        let flows = pipeline.collector("flows").unwrap();
        pipeline
            .push(
                flows,
                vec![Item::Record(record(6)), Item::Record(record(17))],
            )
            .unwrap();

        // Two records to `everything`, one to `tcp_only`.
        assert_eq!(out.lock().unwrap().items.len(), 3);
    }

    #[test]
    fn bad_configurations_say_what_is_wrong() {
        let out = Shared::default();
        let registry = registry(&out);
        let build = |text: &str| {
            let text = format!("[collectors.flows]\ntype = \"netflow\"\n{text}");
            Config::parse(&text)
                .and_then(|config| config.build(&registry).map(|_| ()))
                .err()
                .unwrap()
                .to_string()
        };

        assert!(matches!(
            Config::parse("[processes]").and_then(|c| c.build(&registry).map(|_| ())),
            Err(Error::NoCollectors)
        ));
        assert_eq!(build(""), "the pipeline has no exporter");
        assert!(matches!(
            Config::parse("[collectors.flows]\ntype = \"netflow\"\n[extra]"),
            Err(Error::Parse(_))
        ));
        assert_eq!(
            build("[exporters.out]\ntype = \"kafka\"\ninputs = [\"flows\"]"),
            "unknown exporter type 'kafka'"
        );
        assert_eq!(
            build(
                "[processes.t]\ntype = \"dedup\"\ninputs = [\"flows\"]\n[exporters.out]\ntype = \"collect\"\ninputs = [\"t\"]"
            ),
            "unknown process type 'dedup'"
        );
        assert_eq!(
            build(
                "[processes.t]\ntype = \"select\"\ninputs = [\"flows\"]\n[exporters.out]\ntype = \"collect\"\ninputs = [\"t\"]"
            ),
            "t: select needs a protocol number"
        );
        assert_eq!(
            build("[exporters.out]\ntype = \"collect\"\ninputs = [\"nothing\"]"),
            "out: unknown input 'nothing'"
        );
    }
}
