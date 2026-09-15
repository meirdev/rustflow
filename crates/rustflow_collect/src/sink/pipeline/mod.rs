//! The pipeline between the ingest thread and the encoder thread: decoded
//! flows, or raw packets already serialized, cross it in chunks.

pub mod errors;
pub mod timer;

use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{io, thread};

use chrono::Utc;
pub use errors::SinkErrors;
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;
pub use timer::FlushTimer;

use crate::enrich::{Enriched, EnrichmentEngine};
use crate::sink::{OutputMetrics, RotatingSink, Serialization};

/// How often buffered output is pushed out when flows trickle in too slowly
/// to fill the write buffer.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Records accumulated per channel send. Per-packet sends (mutex + condvar
/// per packet) measurably dominate the pipeline's overhead; chunking
/// amortizes them ~25x at 10 flows/packet.
const CHUNK_RECORDS: usize = 256;

/// A partial chunk waits at most this long. It is also the ingest loop's
/// socket read timeout, so an idle loop wakes up to hand its chunk over.
pub const CHUNK_FLUSH_TIMEOUT: Duration = Duration::from_millis(100);

/// Depth of the ingest -> encoder channel, in chunks (~256 flows each).
/// Deep enough to absorb encoder stalls (row-group flushes, file rotation)
/// without dropping, yet bounded by design: when the encoder truly falls
/// behind, ingest blocks, the socket buffer fills, and the kernel drops
/// (visibly in its counters) — memory can never grow without limit.
/// Worst case ~260k buffered flows, on the order of 100 MB.
const PIPELINE_DEPTH: usize = 1024;

/// What crosses the channel: decoded flows for `--format common`, or the
/// JSON lines the ingest thread wrote for `--format raw`.
pub enum Chunk {
    Flows(Vec<CommonFlow>),
    Raw(Vec<u8>),
}

/// The ingest thread's end of the pipeline: batches records into chunks
/// and hands them to the encoder thread over a bounded channel. Dropping
/// the sender closes the channel; the encoder then drains every queued
/// chunk, finalizes the output, and `join` returns — so nothing decoded
/// before shutdown is lost.
pub struct Pipeline {
    tx: mpsc::SyncSender<Chunk>,
    handle: thread::JoinHandle<io::Result<()>>,
    flows: Vec<CommonFlow>,
    raw: Vec<u8>,
    raw_records: usize,
    /// A discard sink never looks at raw bytes, so they are not produced.
    discard: bool,
    /// When the first record of the current chunk arrived.
    chunk_started: Instant,
}

impl Pipeline {
    /// Spawn the encoder thread: it owns enrichment + serialization + writing,
    /// so the ingest thread only decodes.
    pub fn spawn(sink: RotatingSink, enrichment: EnrichmentEngine, metrics: OutputMetrics) -> Self {
        let discard = sink.serialization() == Serialization::Discard;
        let (tx, rx) = mpsc::sync_channel::<Chunk>(PIPELINE_DEPTH);
        // Returns once the channel is closed (ingest ended) and the output
        // is finished; for parquet that includes the footer.
        let handle = thread::spawn(move || encoder_loop(rx, sink, &enrichment, &metrics));
        Self {
            tx,
            handle,
            flows: Vec::with_capacity(CHUNK_RECORDS),
            raw: Vec::new(),
            raw_records: 0,
            discard,
            chunk_started: Instant::now(),
        }
    }

    /// Queue decoded flows; sends to the encoder once a chunk is full or
    /// has waited long enough, so a slow trickle is not held back.
    pub fn push(&mut self, flows: impl IntoIterator<Item = CommonFlow>) {
        self.start_chunk();
        self.flows.extend(flows);
        self.send_if_ready(self.flows.len());
    }

    /// Queue a raw packet as one JSON line.
    pub fn push_raw<T: Serialize + ?Sized>(&mut self, record: &T) {
        if self.discard {
            return;
        }
        self.start_chunk();
        serde_json::to_writer(&mut self.raw, record).expect("packet types serialize");
        self.raw.push(b'\n');
        self.raw_records += 1;
        self.send_if_ready(self.raw_records);
    }

    fn start_chunk(&mut self) {
        if self.flows.is_empty() && self.raw.is_empty() {
            self.chunk_started = Instant::now();
        }
    }

    fn send_if_ready(&mut self, records: usize) {
        if records >= CHUNK_RECORDS || self.chunk_started.elapsed() >= CHUNK_FLUSH_TIMEOUT {
            self.flush();
        }
    }

    /// Send whatever is buffered, even a partial chunk (idle / shutdown).
    pub fn flush(&mut self) {
        if !self.flows.is_empty() {
            let full = std::mem::replace(&mut self.flows, Vec::with_capacity(CHUNK_RECORDS));
            self.send(Chunk::Flows(full));
        }
        if !self.raw.is_empty() {
            let full = std::mem::take(&mut self.raw);
            self.raw_records = 0;
            self.send(Chunk::Raw(full));
        }
    }

    fn send(&self, chunk: Chunk) {
        if self.tx.send(chunk).is_err() {
            // The receiver is gone only if the encoder thread panicked.
            // Continuing would silently discard every record from here on.
            eprintln!("Encoder thread has died; exiting");
            std::process::exit(1);
        }
    }

    /// Flush, close the channel, and wait for the encoder to write
    /// everything out.
    pub fn drain(mut self) -> io::Result<()> {
        self.flush();
        let Self { tx, handle, .. } = self;
        drop(tx);
        handle
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("encoder thread panicked")))
    }
}

/// The encoder thread's body: drains chunks until every sender is gone,
/// then finishes the output. Rotation is checked per chunk and on the
/// flush deadline, so an idle pipeline still closes its window on time.
pub fn encoder_loop(
    rx: Receiver<Chunk>,
    mut sink: RotatingSink,
    enrichment: &EnrichmentEngine,
    metrics: &OutputMetrics,
) -> io::Result<()> {
    let mut enriched = Enriched::new(enrichment.output_fields().len());
    let mut errors = SinkErrors::new(metrics);
    let mut timer = FlushTimer::new(FLUSH_INTERVAL);

    loop {
        match rx.recv_timeout(timer.remaining()) {
            Ok(chunk) => {
                errors.rotate(sink.rotate_if_due(Utc::now()));
                match chunk {
                    Chunk::Flows(flows) => {
                        for flow in &flows {
                            enrichment.enrich(flow, &mut enriched);
                            errors.write(sink.write(flow, &enriched));
                        }
                        metrics.flows.inc_by(flows.len() as u64);
                    }
                    Chunk::Raw(lines) => errors.write(sink.write_raw(&lines)),
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if timer.due() {
            errors.rotate(sink.rotate_if_due(Utc::now()));
            errors.flush(sink.flush());
        }
    }
    sink.finish()
}
