use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{fmt, io};

use crate::{CollectorId, Item, Pipeline};

/// How the mediation thread paces itself.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// How often the pipeline ticks: windows close and exporters flush.
    pub tick_every: Duration,
    /// Chunks that may wait between the collectors and the pipeline. When
    /// it is full, collectors block on [`Feed::push`]: the pipeline's pace
    /// bounds memory, and the loss, if any, happens in the kernel's
    /// socket buffers where it is counted.
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

struct Chunk {
    collector: CollectorId,
    items: Vec<Item>,
}

/// Runs a [`Pipeline`] on a thread of its own, fed by the collectors
/// through [`Feed`]s. Export failures go to the error callback as they
/// happen; the pipeline keeps running.
pub struct Runner {
    tx: SyncSender<Chunk>,
    thread: JoinHandle<io::Result<()>>,
}

impl Runner {
    pub fn spawn(
        pipeline: Pipeline,
        schedule: Schedule,
        on_error: impl FnMut(io::Error) + Send + 'static,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(schedule.queue);
        let thread = thread::Builder::new()
            .name("mediator".into())
            .spawn(move || run(pipeline, rx, schedule.tick_every, on_error))?;
        Ok(Self { tx, thread })
    }

    /// A collector's way into the pipeline.
    pub fn feed(&self, collector: CollectorId) -> Feed {
        Feed {
            tx: self.tx.clone(),
            collector,
        }
    }

    /// Waits for every chunk pushed so far to go through, then ends the
    /// stream. Every [`Feed`] must be dropped first, or this never
    /// returns.
    pub fn finish(self) -> io::Result<()> {
        drop(self.tx);
        self.thread
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the mediation thread panicked")))
    }
}

/// A collector's end of the queue into the pipeline.
#[derive(Clone)]
pub struct Feed {
    tx: SyncSender<Chunk>,
    collector: CollectorId,
}

impl Feed {
    /// Queues `items`, waiting for room if the pipeline is behind.
    pub fn push(&self, items: Vec<Item>) -> Result<(), Closed> {
        if items.is_empty() {
            return Ok(());
        }
        self.tx
            .send(Chunk {
                collector: self.collector,
                items,
            })
            .map_err(|_| Closed)
    }
}

/// The pipeline is gone, which happens only if its thread panicked;
/// nothing pushed from here on would be exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the pipeline is closed")
    }
}

impl std::error::Error for Closed {}

fn run(
    mut pipeline: Pipeline,
    rx: Receiver<Chunk>,
    tick_every: Duration,
    mut on_error: impl FnMut(io::Error),
) -> io::Result<()> {
    // Ticks are due at fixed times, not `tick_every` after the last
    // chunk, so a steady stream never starves them.
    let mut next_tick = Instant::now() + tick_every;
    loop {
        match rx.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
            Ok(chunk) => {
                if let Err(e) = pipeline.push(chunk.collector, chunk.items) {
                    on_error(e);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() >= next_tick {
            if let Err(e) = pipeline.tick(SystemTime::now()) {
                on_error(e);
            }
            next_tick += tick_every;
            if next_tick < Instant::now() {
                next_tick = Instant::now() + tick_every;
            }
        }
    }
    pipeline.finish()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::pipeline::tests::{Collect, Hold, Shared, record};

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
        let netflow = pipeline.collector("netflow").unwrap();
        let sflow = pipeline.collector("sflow").unwrap();
        let runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();

        let feeds = [(runner.feed(netflow), 6), (runner.feed(sflow), 17)];
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
        let netflow = pipeline.collector("netflow").unwrap();
        let schedule = Schedule {
            tick_every: Duration::from_millis(20),
            queue: 4,
        };
        let runner = Runner::spawn(pipeline, schedule, |e| panic!("{e}")).unwrap();
        let feed = runner.feed(netflow);

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
    fn export_failures_are_reported_and_do_not_stop_the_run() {
        struct Failing;

        impl crate::Exporter for Failing {
            fn export(&mut self, _: &[Item]) -> io::Result<()> {
                Err(io::Error::other("disk full"))
            }
        }

        let pipeline = Pipeline::builder(["netflow"])
            .exporter("files", ["netflow"], Box::new(Failing))
            .build()
            .unwrap();
        let netflow = pipeline.collector("netflow").unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&errors);
        let runner = Runner::spawn(pipeline, Schedule::default(), move |e| {
            seen.lock().unwrap().push(e.to_string());
        })
        .unwrap();
        let feed = runner.feed(netflow);

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
    fn a_feed_outliving_the_runner_learns_it_is_closed() {
        let (pipeline, _out) = pipeline(false);
        let netflow = pipeline.collector("netflow").unwrap();
        let runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
        let feed = runner.feed(netflow);
        let thread = thread::spawn(move || runner.finish());

        // The runner waits for the feed; once it is gone, the thread ends.
        thread::sleep(Duration::from_millis(20));
        assert!(!thread.is_finished());
        drop(feed);
        thread.join().unwrap().unwrap();
    }
}
