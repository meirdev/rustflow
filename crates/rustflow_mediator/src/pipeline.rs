use std::io;
use std::time::SystemTime;

use crate::{Error, Exporter, Item, Meter, Output, Process};

/// A source of records, a collector or a meter: see [`Pipeline::source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId(pub(crate) usize);

/// Where a component's input comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Node {
    Source(usize),
    Process(usize),
}

pub(crate) struct Component<T> {
    pub(crate) name: String,
    pub(crate) inputs: Vec<Node>,
    pub(crate) inner: T,
}

/// A pipeline taken apart, for running its components on threads of
/// their own.
pub(crate) struct Parts {
    pub(crate) sources: Vec<String>,
    /// The last sources, one meter each.
    pub(crate) meters: Vec<Box<dyn Meter>>,
    pub(crate) processes: Vec<Component<Box<dyn Process>>>,
    pub(crate) exporters: Vec<Component<Box<dyn Exporter>>>,
}

/// Named Collecting, Metering, Intermediate and Exporting Processes (RFC
/// 6183 section 5) wired by their inputs. Built by a [`Builder`], or from
/// a [`Config`](crate::Config).
pub struct Pipeline {
    /// Collectors, then meters.
    sources: Vec<String>,
    meters: Vec<Box<dyn Meter>>,
    /// In an order where every process comes after its inputs.
    processes: Vec<Component<Box<dyn Process>>>,
    exporters: Vec<Component<Box<dyn Exporter>>>,
    /// How many components read each source, then each process.
    readers: Vec<usize>,
}

impl Pipeline {
    /// A builder with the named collectors as sources.
    pub fn builder(collectors: impl IntoIterator<Item = impl Into<String>>) -> Builder {
        Builder {
            sources: collectors.into_iter().map(Into::into).collect(),
            meters: Vec::new(),
            processes: Vec::new(),
            exporters: Vec::new(),
        }
    }

    /// The source called `name`, to push items from, or to get the feed
    /// of.
    pub fn source(&self, name: &str) -> Option<SourceId> {
        self.sources.iter().position(|s| s == name).map(SourceId)
    }

    pub(crate) fn into_parts(self) -> Parts {
        Parts {
            sources: self.sources,
            meters: self.meters,
            processes: self.processes,
            exporters: self.exporters,
        }
    }

    /// Runs `items` from `source` through every process and exporter they
    /// reach. Every exporter runs; the first export failure is returned.
    pub fn push(&mut self, source: SourceId, items: Vec<Item>) -> io::Result<()> {
        let mut batches = Batches::new(self.sources.len(), &self.readers);
        batches.put(Node::Source(source.0), items);
        self.run(&mut batches, |_, _| {});
        self.deliver(&mut batches, |_, _| Ok(()))
    }

    /// Ticks every process and flushes every exporter, whether or not
    /// anything reached it.
    pub fn tick(&mut self, now: SystemTime) -> io::Result<()> {
        let mut batches = Batches::new(self.sources.len(), &self.readers);
        self.run(&mut batches, |process, out| process.tick(now, out));
        self.deliver(&mut batches, |exporter, _| exporter.flush())
    }

    /// Ends the stream: every process emits what it holds, every exporter
    /// completes its output.
    pub fn finish(mut self) -> io::Result<()> {
        let mut batches = Batches::new(self.sources.len(), &self.readers);
        self.run(&mut batches, |process, out| process.finish(out));
        let mut result = Ok(());
        for mut exporter in self.exporters {
            let items = batches.gather(&exporter.inputs);
            let exported =
                export(exporter.inner.as_mut(), &items).and_then(|()| exporter.inner.finish());
            result = result.and(named(&exporter.name, exported));
        }
        result
    }

    /// Runs every process on what its inputs produced, then `then` on
    /// it, keeping what it emitted for the components that read it.
    fn run(&mut self, batches: &mut Batches, mut then: impl FnMut(&mut dyn Process, &mut Output)) {
        for (index, process) in self.processes.iter_mut().enumerate() {
            let items = batches.gather(&process.inputs);
            let mut out = Output::with_capacity(items.len());
            for item in items {
                process.inner.item(item, &mut out);
            }
            then(process.inner.as_mut(), &mut out);
            batches.put(Node::Process(index), out.into_items());
        }
    }

    /// Hands every exporter what reached it, then `then`. Every exporter
    /// gets its turn; the first failure is returned.
    fn deliver(
        &mut self,
        batches: &mut Batches,
        mut then: impl FnMut(&mut dyn Exporter, &[Item]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut result = Ok(());
        for exporter in &mut self.exporters {
            let items = batches.gather(&exporter.inputs);
            let delivered = export(exporter.inner.as_mut(), &items)
                .and_then(|()| then(exporter.inner.as_mut(), &items));
            result = result.and(named(&exporter.name, delivered));
        }
        result
    }
}

fn export(exporter: &mut dyn Exporter, items: &[Item]) -> io::Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    exporter.export(items)
}

/// An exporter's failure, saying which exporter.
fn named(exporter: &str, result: io::Result<()>) -> io::Result<()> {
    result.map_err(|e| io::Error::new(e.kind(), format!("{exporter}: {e}")))
}

/// What each node produced in one pass, handed to its readers: copied to
/// all but the last, which takes the original.
struct Batches {
    sources: usize,
    items: Vec<Option<Vec<Item>>>,
    readers_left: Vec<usize>,
}

impl Batches {
    fn new(sources: usize, readers: &[usize]) -> Self {
        Self {
            sources,
            items: vec![None; readers.len()],
            readers_left: readers.to_vec(),
        }
    }

    /// Sources first, then processes, in one index space.
    fn index(&self, node: Node) -> usize {
        match node {
            Node::Source(i) => i,
            Node::Process(i) => self.sources + i,
        }
    }

    fn put(&mut self, node: Node, items: Vec<Item>) {
        if !items.is_empty() {
            let i = self.index(node);
            self.items[i] = Some(items);
        }
    }

    fn gather(&mut self, inputs: &[Node]) -> Vec<Item> {
        let mut gathered = Vec::new();
        for &input in inputs {
            let i = self.index(input);
            self.readers_left[i] -= 1;
            let items = if self.readers_left[i] == 0 {
                self.items[i].take()
            } else {
                self.items[i].clone()
            };
            gathered.extend(items.unwrap_or_default());
        }
        gathered
    }
}

/// Assembles a pipeline, checking that every input names a source or a
/// process, that every component has one, and that nothing feeds itself.
pub struct Builder {
    sources: Vec<String>,
    meters: Vec<Box<dyn Meter>>,
    processes: Vec<(String, Vec<String>, Box<dyn Process>)>,
    exporters: Vec<(String, Vec<String>, Box<dyn Exporter>)>,
}

impl Builder {
    /// Adds a meter as a source called `name`.
    pub fn meter(mut self, name: impl Into<String>, meter: Box<dyn Meter>) -> Self {
        self.sources.push(name.into());
        self.meters.push(meter);
        self
    }

    pub fn process(
        mut self,
        name: impl Into<String>,
        inputs: impl IntoIterator<Item = impl Into<String>>,
        process: Box<dyn Process>,
    ) -> Self {
        self.processes.push((
            name.into(),
            inputs.into_iter().map(Into::into).collect(),
            process,
        ));
        self
    }

    pub fn exporter(
        mut self,
        name: impl Into<String>,
        inputs: impl IntoIterator<Item = impl Into<String>>,
        exporter: Box<dyn Exporter>,
    ) -> Self {
        self.exporters.push((
            name.into(),
            inputs.into_iter().map(Into::into).collect(),
            exporter,
        ));
        self
    }

    pub fn build(self) -> Result<Pipeline, Error> {
        if self.exporters.is_empty() {
            return Err(Error::NoExporters);
        }
        let mut names: Vec<&str> = Vec::new();
        let process_names = self.processes.iter().map(|(name, _, _)| name);
        let exporter_names = self.exporters.iter().map(|(name, _, _)| name);
        for name in self
            .sources
            .iter()
            .chain(process_names)
            .chain(exporter_names)
        {
            if names.contains(&name.as_str()) {
                return Err(Error::DuplicateName(name.clone()));
            }
            names.push(name);
        }

        let resolve = |name: &str, inputs: &[String]| -> Result<Vec<Node>, Error> {
            if inputs.is_empty() {
                return Err(Error::NoInputs(name.to_owned()));
            }
            inputs
                .iter()
                .map(|input| {
                    if let Some(i) = self.sources.iter().position(|s| s == input) {
                        Ok(Node::Source(i))
                    } else if let Some(i) = self.processes.iter().position(|(n, _, _)| n == input) {
                        Ok(Node::Process(i))
                    } else {
                        Err(Error::UnknownInput {
                            component: name.to_owned(),
                            input: input.clone(),
                        })
                    }
                })
                .collect()
        };
        let process_inputs = self
            .processes
            .iter()
            .map(|(name, inputs, _)| resolve(name, inputs))
            .collect::<Result<Vec<_>, _>>()?;
        let exporter_inputs = self
            .exporters
            .iter()
            .map(|(name, inputs, _)| resolve(name, inputs))
            .collect::<Result<Vec<_>, _>>()?;
        let order = topological(&self.processes, &process_inputs)?;

        // Processs are stored in `order`, so inputs are renumbered to
        // their final positions, which is also the index space of
        // `Batches`.
        let sources = self.sources.len();
        let position = |node: Node| match node {
            Node::Source(i) => Node::Source(i),
            Node::Process(i) => Node::Process(order.iter().position(|&o| o == i).unwrap()),
        };
        let mut readers = vec![0; sources + self.processes.len()];
        let mut count = |inputs: &[Node]| {
            for &input in inputs {
                readers[match input {
                    Node::Source(i) => i,
                    Node::Process(i) => sources + i,
                }] += 1;
            }
        };

        let mut by_index: Vec<Option<_>> = self
            .processes
            .into_iter()
            .zip(process_inputs)
            .map(|((name, _, inner), inputs)| {
                let inputs: Vec<Node> = inputs.into_iter().map(position).collect();
                count(&inputs);
                Some(Component {
                    name,
                    inputs,
                    inner,
                })
            })
            .collect();
        let processes = order.iter().map(|&i| by_index[i].take().unwrap()).collect();
        let exporters = self
            .exporters
            .into_iter()
            .zip(exporter_inputs)
            .map(|((name, _, inner), inputs)| {
                let inputs: Vec<Node> = inputs.into_iter().map(position).collect();
                count(&inputs);
                Component {
                    name,
                    inputs,
                    inner,
                }
            })
            .collect();

        Ok(Pipeline {
            sources: self.sources,
            meters: self.meters,
            processes,
            exporters,
            readers,
        })
    }
}

/// Process indexes in an order where every process follows its
/// inputs.
fn topological(
    processes: &[(String, Vec<String>, Box<dyn Process>)],
    inputs: &[Vec<Node>],
) -> Result<Vec<usize>, Error> {
    let mut order = Vec::with_capacity(processes.len());
    let mut placed = vec![false; processes.len()];
    while order.len() < processes.len() {
        let ready = (0..processes.len()).find(|&i| {
            !placed[i]
                && inputs[i].iter().all(|input| match *input {
                    Node::Source(_) => true,
                    Node::Process(j) => placed[j],
                })
        });
        let Some(i) = ready else {
            let stuck = (0..processes.len()).find(|&i| !placed[i]).unwrap();
            return Err(Error::Cycle(processes[stuck].0.clone()));
        };
        placed[i] = true;
        order.push(i);
    }
    Ok(order)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rustflow_convert::{Protocol, Record};
    use rustflow_protocol::information_element::{ElementId, iana};
    use rustflow_protocol::value::Value;

    use super::*;
    use crate::Control;

    pub(crate) fn record(protocol: u8) -> Record {
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 1,
            scope: Vec::new(),
            elements: Arc::from([iana::PROTOCOL_IDENTIFIER]),
            values: vec![Value::Unsigned8(protocol)],
        }
    }

    fn protocol(item: &Item) -> u8 {
        match item {
            Item::Record(record) => match record.first(iana::PROTOCOL_IDENTIFIER) {
                Some(Value::Unsigned8(protocol)) => *protocol,
                other => panic!("unexpected protocol {other:?}"),
            },
            Item::Control(control) => panic!("unexpected {control:?}"),
        }
    }

    /// Keeps records of one protocol.
    pub(crate) struct Select(pub(crate) u8);

    impl Process for Select {
        fn item(&mut self, item: Item, out: &mut Output) {
            if !matches!(&item, Item::Record(_)) || protocol(&item) == self.0 {
                out.push(item);
            }
        }
    }

    /// Adds an element to every record.
    pub(crate) struct Tag(pub(crate) ElementId, pub(crate) Value);

    impl Process for Tag {
        fn item(&mut self, item: Item, out: &mut Output) {
            match item {
                Item::Record(mut record) => {
                    let mut elements = record.elements.to_vec();
                    elements.push(self.0);
                    record.elements = elements.into();
                    record.values.push(self.1.clone());
                    out.record(record);
                }
                control => out.push(control),
            }
        }
    }

    /// Pushes that many records, one chunk each, then ends; or stops
    /// early when told to.
    pub(crate) struct Generate(pub(crate) usize);

    impl Meter for Generate {
        fn run(self: Box<Self>, feed: crate::Feed, stop: crate::Stop) -> io::Result<()> {
            for _ in 0..self.0 {
                if stop.is_set() {
                    break;
                }
                feed.push(vec![Item::Record(record(6))])
                    .map_err(io::Error::other)?;
            }
            Ok(())
        }
    }

    /// Holds records and emits them on a tick or at the end.
    #[derive(Default)]
    pub(crate) struct Hold(Vec<Item>);

    impl Process for Hold {
        fn item(&mut self, item: Item, _out: &mut Output) {
            self.0.push(item);
        }

        fn tick(&mut self, _now: SystemTime, out: &mut Output) {
            for item in self.0.drain(..) {
                out.push(item);
            }
        }

        fn finish(&mut self, out: &mut Output) {
            for item in self.0.drain(..) {
                out.push(item);
            }
        }
    }

    #[derive(Default)]
    pub(crate) struct Exported {
        pub(crate) items: Vec<Item>,
        pub(crate) flushes: usize,
        pub(crate) finished: bool,
    }

    pub(crate) type Shared = Arc<Mutex<Exported>>;

    pub(crate) struct Collect(pub(crate) Shared);

    impl Exporter for Collect {
        fn export(&mut self, items: &[Item]) -> io::Result<()> {
            self.0.lock().unwrap().items.extend_from_slice(items);
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flushes += 1;
            Ok(())
        }

        fn finish(self: Box<Self>) -> io::Result<()> {
            self.0.lock().unwrap().finished = true;
            Ok(())
        }
    }

    struct Failing;

    impl Exporter for Failing {
        fn export(&mut self, _: &[Item]) -> io::Result<()> {
            Err(io::Error::other("disk full"))
        }
    }

    fn collect() -> (Box<dyn Exporter>, Shared) {
        let shared = Shared::default();
        (Box::new(Collect(Arc::clone(&shared))), shared)
    }

    #[test]
    fn items_reach_each_exporter_through_the_processes_it_names() {
        let (parquet, parquet_out) = collect();
        let (ipfix, ipfix_out) = collect();
        let mut pipeline = Pipeline::builder(["flows"])
            .process(
                "names",
                ["flows"],
                Box::new(Tag(iana::INGRESS_INTERFACE, Value::Unsigned32(7))),
            )
            .process("tcp", ["names"], Box::new(Select(6)))
            .exporter("parquet", ["tcp"], parquet)
            .exporter("collector", ["names"], ipfix)
            .build()
            .unwrap();
        let flows = pipeline.source("flows").unwrap();
        assert_eq!(pipeline.source("logs"), None);

        pipeline
            .push(
                flows,
                vec![
                    Item::Record(record(6)),
                    Item::Record(record(17)),
                    Item::Control(Control::SessionClosed {
                        exporter: [192, 0, 2, 1].into(),
                    }),
                ],
            )
            .unwrap();

        let parquet_out = parquet_out.lock().unwrap();
        assert_eq!(parquet_out.items.len(), 2);
        assert_eq!(protocol(&parquet_out.items[0]), 6);
        assert!(matches!(parquet_out.items[1], Item::Control(_)));
        let ipfix_out = ipfix_out.lock().unwrap();
        assert_eq!(ipfix_out.items.len(), 3);
        let Item::Record(tagged) = &ipfix_out.items[1] else {
            panic!("expected a record");
        };
        assert_eq!(
            tagged.first(iana::INGRESS_INTERFACE),
            Some(&Value::Unsigned32(7))
        );
        assert_eq!(ipfix_out.flushes, 0);
        assert!(!ipfix_out.finished);
    }

    #[test]
    fn a_component_may_read_several_inputs() {
        let (exporter, out) = collect();
        let mut pipeline = Pipeline::builder(["netflow", "sflow"])
            .process("tcp", ["netflow"], Box::new(Select(6)))
            .exporter("all", ["tcp", "sflow"], exporter)
            .build()
            .unwrap();

        let netflow = pipeline.source("netflow").unwrap();
        let sflow = pipeline.source("sflow").unwrap();
        pipeline
            .push(
                netflow,
                vec![Item::Record(record(6)), Item::Record(record(17))],
            )
            .unwrap();
        pipeline
            .push(sflow, vec![Item::Record(record(17))])
            .unwrap();

        let protocols: Vec<u8> = out.lock().unwrap().items.iter().map(protocol).collect();
        assert_eq!(protocols, [6, 17]);
    }

    #[test]
    fn ticks_release_held_items_through_later_processes_and_flush() {
        let (exporter, out) = collect();
        let mut pipeline = Pipeline::builder(["flows"])
            .process("hold", ["flows"], Box::new(Hold::default()))
            .process("tcp", ["hold"], Box::new(Select(6)))
            .exporter("out", ["tcp"], exporter)
            .build()
            .unwrap();
        let flows = pipeline.source("flows").unwrap();

        pipeline
            .push(
                flows,
                vec![Item::Record(record(6)), Item::Record(record(17))],
            )
            .unwrap();
        assert!(out.lock().unwrap().items.is_empty());

        pipeline
            .tick(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        let exported = out.lock().unwrap();
        assert_eq!(exported.items.len(), 1);
        assert_eq!(protocol(&exported.items[0]), 6);
        assert_eq!(exported.flushes, 1);
    }

    #[test]
    fn finishing_drains_every_process_and_completes_every_exporter() {
        let (exporter, out) = collect();
        let mut pipeline = Pipeline::builder(["flows"])
            .process("hold", ["flows"], Box::new(Hold::default()))
            .exporter("out", ["hold"], exporter)
            .build()
            .unwrap();
        let flows = pipeline.source("flows").unwrap();
        pipeline.push(flows, vec![Item::Record(record(1))]).unwrap();

        pipeline.finish().unwrap();

        let exported = out.lock().unwrap();
        assert_eq!(exported.items.len(), 1);
        assert!(exported.finished);
    }

    #[test]
    fn a_failing_exporter_does_not_stop_the_others() {
        let (exporter, out) = collect();
        let mut pipeline = Pipeline::builder(["flows"])
            .exporter("bad", ["flows"], Box::new(Failing))
            .exporter("good", ["flows"], exporter)
            .build()
            .unwrap();
        let flows = pipeline.source("flows").unwrap();

        let error = pipeline
            .push(flows, vec![Item::Record(record(1))])
            .unwrap_err();

        assert_eq!(error.to_string(), "bad: disk full");
        assert_eq!(out.lock().unwrap().items.len(), 1);
    }

    #[test]
    fn wiring_mistakes_are_named() {
        let error = |builder: Builder| builder.build().err().unwrap().to_string();

        assert_eq!(
            error(Pipeline::builder(["flows"])),
            "the pipeline has no exporter"
        );
        assert_eq!(
            error(Pipeline::builder(["flows"]).exporter("out", ["logs"], collect().0)),
            "out: unknown input 'logs'"
        );
        assert_eq!(
            error(Pipeline::builder(["flows"]).exporter("out", Vec::<String>::new(), collect().0)),
            "out: no inputs"
        );
        assert_eq!(
            error(
                Pipeline::builder(["flows"])
                    .process("flows", ["flows"], Box::new(Select(6)))
                    .exporter("out", ["flows"], collect().0)
            ),
            "the name 'flows' is used twice"
        );
        assert_eq!(
            error(
                Pipeline::builder(["flows"])
                    .process("a", ["b"], Box::new(Select(6)))
                    .process("b", ["a", "flows"], Box::new(Select(6)))
                    .exporter("out", ["a"], collect().0)
            ),
            "a is fed by itself, through its inputs"
        );
    }
}
