use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{fmt, io};

use crate::pipeline::{Component, Node, Parts};
use crate::{Exporter, Item, Output, Pipeline, Process, SourceId, Stop};

/// How the runner paces itself.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// How often every component ticks: windows close and exporters
    /// flush.
    pub tick_every: Duration,
    /// Chunks that may wait in each component's inbox. When an inbox is
    /// full, whoever feeds it blocks, up to the collectors on
    /// [`Feed::push`]: the slowest component's pace bounds memory, and the
    /// loss, if any, happens in the kernel's socket buffers where it is
    /// counted.
    pub queue: usize,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            tick_every: Duration::from_millis(250),
            queue: 1024,
        }
    }
}

enum Message {
    Items(Vec<Item>),
    Tick(SystemTime),
    /// One input of the receiver has ended; it ends once all have.
    Finish,
}

type Inbox = SyncSender<Message>;

/// Runs every component of a [`Pipeline`] on a thread of its own, each
/// handing what it emits to the inboxes of the components that read it.
/// Collectors feed the pipeline through a [`Feed`] each; meters run on
/// threads of their own with theirs. Export failures go to the error
/// callback as they happen; the run goes on.
pub struct Runner {
    feeds: Vec<Option<Feed>>,
    stop: Stop,
    meters: Vec<JoinHandle<io::Result<()>>>,
    stop_ticking: mpsc::Sender<()>,
    ticker: JoinHandle<()>,
    threads: Vec<JoinHandle<io::Result<()>>>,
}

impl Runner {
    pub fn spawn(
        pipeline: Pipeline,
        schedule: Schedule,
        on_error: impl FnMut(io::Error) + Send + 'static,
    ) -> io::Result<Self> {
        let Parts {
            sources,
            meters,
            processes,
            exporters,
        } = pipeline.into_parts();
        let on_error: Arc<Mutex<dyn FnMut(io::Error) + Send>> = Arc::new(Mutex::new(on_error));

        let (process_inboxes, process_rxs): (Vec<Inbox>, Vec<_>) = processes
            .iter()
            .map(|_| mpsc::sync_channel(schedule.queue))
            .unzip();
        let (exporter_inboxes, exporter_rxs): (Vec<Inbox>, Vec<_>) = exporters
            .iter()
            .map(|_| mpsc::sync_channel(schedule.queue))
            .unzip();
        let readers_of = |node: Node| -> Vec<Inbox> {
            let of_processes = processes
                .iter()
                .zip(&process_inboxes)
                .filter(|(process, _)| process.inputs.contains(&node));
            let of_exporters = exporters
                .iter()
                .zip(&exporter_inboxes)
                .filter(|(exporter, _)| exporter.inputs.contains(&node));
            of_processes
                .map(|(_, inbox)| inbox)
                .chain(of_exporters.map(|(_, inbox)| inbox))
                .cloned()
                .collect()
        };

        let mut feeds: Vec<Option<Feed>> = (0..sources.len())
            .map(|i| {
                Some(Feed {
                    readers: Readers(readers_of(Node::Source(i))),
                })
            })
            .collect();
        let process_readers: Vec<Readers> = (0..processes.len())
            .map(|i| Readers(readers_of(Node::Process(i))))
            .collect();

        let mut threads = Vec::with_capacity(processes.len() + exporters.len());
        for ((process, rx), readers) in processes.into_iter().zip(process_rxs).zip(process_readers)
        {
            let name = process.name.clone();
            threads.push(spawn(&name, move || {
                run_process(process, rx, &readers);
                Ok(())
            })?);
        }
        for (exporter, rx) in exporters.into_iter().zip(exporter_rxs) {
            let on_error = Arc::clone(&on_error);
            let name = exporter.name.clone();
            threads.push(spawn(&name, move || run_exporter(exporter, rx, &on_error))?);
        }

        let stop = Stop::default();
        let first_meter = sources.len() - meters.len();
        let mut meter_threads = Vec::with_capacity(meters.len());
        for (i, meter) in meters.into_iter().enumerate() {
            let feed = feeds[first_meter + i].take().unwrap_or_else(|| Feed {
                readers: Readers(Vec::new()),
            });
            let stop = stop.clone();
            meter_threads.push(spawn(&sources[first_meter + i], move || {
                meter.run(feed, stop)
            })?);
        }

        let inboxes: Vec<Inbox> = process_inboxes
            .into_iter()
            .chain(exporter_inboxes)
            .collect();
        let (stop_ticking, ticks) = mpsc::channel();
        let ticker = thread::Builder::new()
            .name("mediator:ticker".into())
            .spawn(move || tick(&inboxes, schedule.tick_every, &ticks))?;

        Ok(Self {
            feeds,
            stop,
            meters: meter_threads,
            stop_ticking,
            ticker,
            threads,
        })
    }

    /// A collector's way into the pipeline, given out once per collector.
    /// A meter has its own, so `None` for one.
    pub fn feed(&mut self, collector: SourceId) -> Option<Feed> {
        self.feeds.get_mut(collector.0).and_then(Option::take)
    }

    /// What tells the meters to stop, for a signal handler to set: a
    /// meter with no end of its own runs until then.
    pub fn stop(&self) -> Stop {
        self.stop.clone()
    }

    /// Waits for every meter to end and every chunk pushed so far to go
    /// through, then ends the stream. Every [`Feed`] given out must be
    /// dropped first, and every meter without an end told to
    /// [`stop`](Runner::stop), or this never returns.
    pub fn finish(self) -> io::Result<()> {
        let mut result = Ok(());
        for meter in self.meters {
            let ended = meter
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("a meter's thread panicked")));
            result = result.and(ended);
        }
        // Collectors never fed end their inputs here.
        drop(self.feeds);
        for thread in self.threads {
            let ended = thread
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("a component's thread panicked")));
            result = result.and(ended);
        }
        drop(self.stop_ticking);
        let _ = self.ticker.join();
        result
    }
}

/// A collector's end of the queue into the pipeline. Dropping it tells
/// the components it feeds that this collector is done.
pub struct Feed {
    readers: Readers,
}

impl Feed {
    /// Queues `items` for every component reading this collector, waiting
    /// for room wherever an inbox is full.
    pub fn push(&self, items: Vec<Item>) -> Result<(), Closed> {
        if items.is_empty() {
            return Ok(());
        }
        fan_out(&self.readers.0, items).map_err(|_| Closed)
    }
}

/// The inboxes of the components reading one source or process. Dropping
/// it tells them that it ended, so that a panic ends what it fed as a
/// return does, and shutdown does not wait on them forever.
struct Readers(Vec<Inbox>);

impl Drop for Readers {
    fn drop(&mut self) {
        for reader in &self.0 {
            let _ = reader.send(Message::Finish);
        }
    }
}

/// The pipeline is gone, which happens only if a component's thread
/// panicked; nothing pushed from here on would be exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the pipeline is closed")
    }
}

impl std::error::Error for Closed {}

fn spawn(
    name: &str,
    body: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> io::Result<JoinHandle<io::Result<()>>> {
    thread::Builder::new()
        .name(format!("mediator:{name}"))
        .spawn(body)
}

/// `items` to every reader; the last takes the original, the others a
/// copy. Fails once a reader is gone.
fn fan_out(readers: &[Inbox], items: Vec<Item>) -> Result<(), ()> {
    let mut items = Some(items);
    for (i, reader) in readers.iter().enumerate() {
        let own = if i + 1 == readers.len() {
            items.take().unwrap_or_default()
        } else {
            items.clone().unwrap_or_default()
        };
        reader.send(Message::Items(own)).map_err(|_| ())?;
    }
    Ok(())
}

fn run_process(mut process: Component<Box<dyn Process>>, rx: Receiver<Message>, readers: &Readers) {
    let mut inputs_left = process.inputs.len();
    while let Ok(message) = rx.recv() {
        let mut out = Output::default();
        match message {
            Message::Items(items) => {
                for item in items {
                    process.inner.item(item, &mut out);
                }
            }
            Message::Tick(now) => process.inner.tick(now, &mut out),
            Message::Finish => {
                inputs_left -= 1;
                if inputs_left > 0 {
                    continue;
                }
                process.inner.finish(&mut out);
            }
        }
        let items = out.into_items();
        if !items.is_empty() && fan_out(&readers.0, items).is_err() {
            break;
        }
        if inputs_left == 0 {
            break;
        }
    }
}

fn run_exporter(
    mut exporter: Component<Box<dyn Exporter>>,
    rx: Receiver<Message>,
    on_error: &Mutex<dyn FnMut(io::Error) + Send>,
) -> io::Result<()> {
    let mut inputs_left = exporter.inputs.len();
    while let Ok(message) = rx.recv() {
        let result = match message {
            Message::Items(items) => exporter.inner.export(&items),
            Message::Tick(_) => exporter.inner.flush(),
            Message::Finish => {
                inputs_left -= 1;
                if inputs_left > 0 {
                    continue;
                }
                return exporter
                    .inner
                    .finish()
                    .map_err(|e| named(&exporter.name, e));
            }
        };
        if let Err(e) = result {
            on_error.lock().unwrap_or_else(|p| p.into_inner())(named(&exporter.name, e));
        }
    }
    Ok(())
}

fn named(exporter: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{exporter}: {e}"))
}

/// Ticks every component at fixed times, not `every` after the last
/// one, so a steady stream never starves them. A component that has ended
/// just no longer listens.
fn tick(inboxes: &[Inbox], every: Duration, stop: &Receiver<()>) {
    let mut next = Instant::now() + every;
    loop {
        match stop.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = SystemTime::now();
        for inbox in inboxes {
            let _ = inbox.send(Message::Tick(now));
        }
        next += every;
        if next < Instant::now() {
            next = Instant::now() + every;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::tests::{Collect, Generate, Hold, Shared, Tag, record};

    fn pipeline(hold: bool) -> (Pipeline, Shared) {
        let out = Shared::default();
        let mut builder = Pipeline::builder(["netflow", "sflow"]);
        let inputs: Vec<&str> = if hold {
            builder = builder.process("hold", ["netflow", "sflow"], Box::new(Hold::default()));
            vec!["hold"]
        } else {
            vec!["netflow", "sflow"]
        };
        let pipeline = builder
            .exporter("files", inputs, Box::new(Collect(Arc::clone(&out))))
            .build()
            .unwrap();
        (pipeline, out)
    }

    #[test]
    fn collectors_feed_the_pipeline_from_their_own_threads() {
        let (pipeline, out) = pipeline(false);
        let netflow = pipeline.source("netflow").unwrap();
        let sflow = pipeline.source("sflow").unwrap();
        let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();

        let feeds = [
            (runner.feed(netflow).unwrap(), 6),
            (runner.feed(sflow).unwrap(), 17),
        ];
        assert!(runner.feed(netflow).is_none(), "one feed per collector");
        let threads: Vec<_> = feeds
            .into_iter()
            .map(|(feed, protocol)| {
                thread::spawn(move || {
                    for _ in 0..100 {
                        feed.push(vec![Item::Record(record(protocol))]).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        runner.finish().unwrap();

        let exported = out.lock().unwrap();
        assert_eq!(exported.items.len(), 200);
        assert!(exported.finished);
    }

    #[test]
    fn ticks_come_on_schedule_and_the_end_drains_what_is_held() {
        let (pipeline, out) = pipeline(true);
        let netflow = pipeline.source("netflow").unwrap();
        let schedule = Schedule {
            tick_every: Duration::from_millis(20),
            queue: 4,
        };
        let mut runner = Runner::spawn(pipeline, schedule, |e| panic!("{e}")).unwrap();
        let feed = runner.feed(netflow).unwrap();

        feed.push(vec![Item::Record(record(6))]).unwrap();
        thread::sleep(Duration::from_millis(100));
        {
            let exported = out.lock().unwrap();
            assert_eq!(exported.items.len(), 1, "released by a tick");
            assert!(exported.flushes >= 2, "flushed every tick");
        }

        feed.push(vec![Item::Record(record(17))]).unwrap();
        drop(feed);
        runner.finish().unwrap();

        let exported = out.lock().unwrap();
        assert_eq!(exported.items.len(), 2);
        assert!(exported.finished);
    }

    #[test]
    fn a_process_ends_only_when_all_its_inputs_have() {
        let out = Shared::default();
        let pipeline = Pipeline::builder(["netflow", "sflow"])
            .process(
                "tag",
                ["netflow", "sflow"],
                Box::new(Tag(
                    rustflow_core::protocol::information_element::iana::INGRESS_INTERFACE,
                    rustflow_core::protocol::value::Value::Unsigned32(1),
                )),
            )
            .exporter("files", ["tag"], Box::new(Collect(Arc::clone(&out))))
            .build()
            .unwrap();
        let netflow = pipeline.source("netflow").unwrap();
        let sflow = pipeline.source("sflow").unwrap();
        let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        let netflow = runner.feed(netflow).unwrap();
        let sflow = runner.feed(sflow).unwrap();

        netflow.push(vec![Item::Record(record(6))]).unwrap();
        drop(netflow);
        thread::sleep(Duration::from_millis(20));
        assert!(!out.lock().unwrap().finished, "sflow is still feeding");
        sflow.push(vec![Item::Record(record(17))]).unwrap();
        drop(sflow);
        runner.finish().unwrap();

        let exported = out.lock().unwrap();
        assert_eq!(exported.items.len(), 2);
        assert!(exported.finished);
    }

    #[test]
    fn export_failures_are_reported_and_do_not_stop_the_run() {
        struct Failing;

        impl Exporter for Failing {
            fn export(&mut self, _: &[Item]) -> io::Result<()> {
                Err(io::Error::other("disk full"))
            }
        }

        let pipeline = Pipeline::builder(["netflow"])
            .exporter("files", ["netflow"], Box::new(Failing))
            .build()
            .unwrap();
        let netflow = pipeline.source("netflow").unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&errors);
        let mut runner = Runner::spawn(pipeline, Schedule::default(), move |e| {
            seen.lock().unwrap().push(e.to_string());
        })
        .unwrap();
        let feed = runner.feed(netflow).unwrap();

        feed.push(vec![Item::Record(record(6))]).unwrap();
        feed.push(vec![Item::Record(record(6))]).unwrap();
        drop(feed);
        runner.finish().unwrap();

        assert_eq!(
            *errors.lock().unwrap(),
            ["files: disk full", "files: disk full"]
        );
    }

    #[test]
    fn meters_feed_the_pipeline_from_their_own_threads() {
        let out = Shared::default();
        let pipeline = Pipeline::builder(["netflow"])
            .meter("load", Box::new(Generate(3)))
            .exporter(
                "files",
                ["netflow", "load"],
                Box::new(Collect(Arc::clone(&out))),
            )
            .build()
            .unwrap();
        let netflow = pipeline.source("netflow").unwrap();
        let load = pipeline.source("load").unwrap();
        let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        assert!(runner.feed(load).is_none(), "a meter keeps its own feed");
        let feed = runner.feed(netflow).unwrap();
        feed.push(vec![Item::Record(record(6))]).unwrap();
        drop(feed);
        runner.finish().unwrap();

        assert_eq!(out.lock().unwrap().items.len(), 4);
    }

    #[test]
    fn a_meter_that_never_ends_is_told_to_stop() {
        let out = Shared::default();
        let pipeline = Pipeline::builder(Vec::<String>::new())
            .meter("load", Box::new(Generate(usize::MAX)))
            .exporter("files", ["load"], Box::new(Collect(Arc::clone(&out))))
            .build()
            .unwrap();
        let runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        thread::sleep(Duration::from_millis(20));
        runner.stop().set();
        runner.finish().unwrap();
        assert!(!out.lock().unwrap().items.is_empty());
    }

    #[test]
    fn a_process_that_panics_ends_what_it_feeds() {
        struct Panics;

        impl Process for Panics {
            fn item(&mut self, _: Item, _: &mut Output) {
                panic!("a bug");
            }
        }

        let out = Shared::default();
        let pipeline = Pipeline::builder(["netflow"])
            .process("bug", ["netflow"], Box::new(Panics))
            .exporter("files", ["bug"], Box::new(Collect(Arc::clone(&out))))
            .build()
            .unwrap();
        let netflow = pipeline.source("netflow").unwrap();
        let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        let feed = runner.feed(netflow).unwrap();
        feed.push(vec![Item::Record(record(6))]).unwrap();
        drop(feed);

        let error = runner.finish().unwrap_err();
        assert!(error.to_string().contains("panicked"), "{error}");
        assert!(out.lock().unwrap().finished);
    }

    #[test]
    fn finishing_waits_for_the_feeds() {
        let (pipeline, _out) = pipeline(false);
        let netflow = pipeline.source("netflow").unwrap();
        let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        let feed = runner.feed(netflow).unwrap();
        let thread = thread::spawn(move || runner.finish());

        thread::sleep(Duration::from_millis(20));
        assert!(!thread.is_finished());
        drop(feed);
        thread.join().unwrap().unwrap();
    }
}
