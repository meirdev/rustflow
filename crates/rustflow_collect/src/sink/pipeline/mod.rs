pub mod errors;
pub mod raw;
pub mod timer;

use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{io, thread};

use chrono::Utc;
pub use errors::SinkErrors;
pub use raw::RawOutput;
use rustflow_core::common::common_flow::CommonFlow;
pub use timer::FlushTimer;

use crate::enrich::{Enriched, EnrichmentEngine};
use crate::sink::{self, FlowSink, OutputFormat, OutputMetrics, SinkConfig};

/// How often buffered output is pushed out when flows trickle in too slowly
/// to fill the write buffer.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Raw packets are written on the ingest thread; common flows cross to the
/// encoder thread, which converts them to the destination format.
pub enum Output {
    Raw(Box<RawOutput>),
    Common(Pipeline),
}

impl Output {
    pub fn build(
        format: OutputFormat,
        config: &SinkConfig,
        enrichment: EnrichmentEngine,
        metrics: &OutputMetrics,
    ) -> io::Result<Self> {
        Ok(match format {
            OutputFormat::Raw => Output::Raw(Box::new(RawOutput::new(
                sink::build_raw(config, metrics)?,
                metrics,
            ))),
            OutputFormat::Common => {
                let fields = enrichment.output_fields().to_vec();
                let sink = sink::build(config, fields, metrics)?;
                Output::Common(Pipeline::spawn(sink, enrichment, metrics.clone()))
            }
        })
    }

    /// Nothing arrived for a while: hand over a partial chunk, or flush.
    pub fn idle(&mut self) {
        match self {
            Output::Raw(raw) => raw.idle(),
            Output::Common(pipeline) => pipeline.flush(),
        }
    }

    /// Write everything out and close the output.
    pub fn finish(self) -> io::Result<()> {
        match self {
            Output::Raw(raw) => raw.finish(),
            Output::Common(pipeline) => pipeline.drain(),
        }
    }
}

/// Flows accumulated per channel send. Per-packet sends (mutex + condvar
/// per packet) measurably dominate the pipeline's overhead; chunking
/// amortizes them ~25x at 10 flows/packet.
const CHUNK_FLOWS: usize = 256;

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

/// The ingest thread's end of the pipeline: batches decoded flows into
/// chunks and hands them to the encoder thread over a bounded channel.
/// Dropping the sender closes the channel; the encoder then drains every
/// queued chunk, finalizes the output, and `join` returns — so nothing
/// decoded before shutdown is lost.
pub struct Pipeline {
    tx: mpsc::SyncSender<Vec<CommonFlow>>,
    handle: thread::JoinHandle<io::Result<()>>,
    chunk: Vec<CommonFlow>,
    /// When the first flow of the current chunk arrived.
    chunk_started: Instant,
}

impl Pipeline {
    /// Spawn the encoder thread: it owns enrichment + serialization + writing,
    /// so the ingest thread only decodes.
    pub fn spawn(
        sink: Box<dyn FlowSink>,
        enrichment: EnrichmentEngine,
        metrics: OutputMetrics,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Vec<CommonFlow>>(PIPELINE_DEPTH);
        // Returns once the channel is closed (ingest ended) and the output
        // is finished; for parquet that includes the footer.
        let handle = thread::spawn(move || encoder_loop(rx, sink, &enrichment, &metrics));
        Self {
            tx,
            handle,
            chunk: Vec::with_capacity(CHUNK_FLOWS),
            chunk_started: Instant::now(),
        }
    }

    /// Queue decoded flows; sends to the encoder once a chunk is full or
    /// has waited long enough, so a slow trickle is not held back.
    pub fn push(&mut self, flows: impl IntoIterator<Item = CommonFlow>) {
        if self.chunk.is_empty() {
            self.chunk_started = Instant::now();
        }
        self.chunk.extend(flows);
        if self.chunk.len() >= CHUNK_FLOWS || self.chunk_started.elapsed() >= CHUNK_FLUSH_TIMEOUT {
            self.flush();
        }
    }

    /// Send whatever is buffered, even a partial chunk (idle / shutdown).
    pub fn flush(&mut self) {
        if self.chunk.is_empty() {
            return;
        }
        let full = std::mem::replace(&mut self.chunk, Vec::with_capacity(CHUNK_FLOWS));
        if self.tx.send(full).is_err() {
            // The receiver is gone only if the encoder thread panicked.
            // Continuing would silently discard every flow from here on.
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

/// The encoder thread's body: drains chunks of flows until every sender is
/// gone, then finishes the output. Rotation is checked per chunk and on the
/// flush deadline, so an idle pipeline still rotates its empty window.
pub fn encoder_loop(
    rx: Receiver<Vec<CommonFlow>>,
    mut sink: Box<dyn FlowSink>,
    enrichment: &EnrichmentEngine,
    metrics: &OutputMetrics,
) -> io::Result<()> {
    let mut enriched = Enriched::new(enrichment.output_fields().len());
    let mut errors = SinkErrors::new(metrics);
    let mut timer = FlushTimer::new(FLUSH_INTERVAL);

    loop {
        match rx.recv_timeout(timer.remaining()) {
            Ok(flows) => {
                errors.rotate(sink.rotate_if_due(Utc::now()));
                for flow in &flows {
                    enrichment.enrich(flow, &mut enriched);
                    errors.write(sink.write(flow, &enriched));
                }
                metrics.flows.inc_by(flows.len() as u64);
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
