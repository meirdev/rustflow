use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::{io, thread};

use chrono::Utc;
use rustflow_core::common::common_flow::CommonFlow;

use super::{FLUSH_INTERVAL, FlushTimer, SinkErrors};
use crate::enrich::{Enriched, EnrichmentEngine};
use crate::sink::{FlowSink, OutputMetrics};

/// Flows accumulated per channel send. Per-packet sends (mutex + condvar
/// per packet) measurably dominate the pipeline's overhead; chunking
/// amortizes them ~25x at 10 flows/packet.
const CHUNK_FLOWS: usize = 256;

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
pub struct Encoder {
    tx: Option<mpsc::SyncSender<Vec<CommonFlow>>>,
    handle: Option<thread::JoinHandle<()>>,
    chunk: Vec<CommonFlow>,
}

impl Encoder {
    /// Spawn the encoder thread: it owns enrichment + serialization + writing,
    /// so the ingest thread only decodes.
    pub fn spawn(
        sink: Box<dyn FlowSink>,
        enrichment: EnrichmentEngine,
        metrics: OutputMetrics,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Vec<CommonFlow>>(PIPELINE_DEPTH);
        let handle = thread::spawn(move || {
            // Returns once the channel is closed (ingest ended) and the
            // output is finished; for parquet that includes the footer.
            if let Err(e) = encoder_loop(rx, sink, &enrichment, &metrics) {
                eprintln!("Failed to finalize output: {}", e);
            }
        });
        Self {
            tx: Some(tx),
            handle: Some(handle),
            chunk: Vec::with_capacity(CHUNK_FLOWS),
        }
    }

    /// Queue decoded flows; sends to the encoder once a chunk is full.
    pub fn push(&mut self, flows: impl IntoIterator<Item = CommonFlow>) {
        self.chunk.extend(flows);
        if self.chunk.len() >= CHUNK_FLOWS {
            self.flush();
        }
    }

    /// Send whatever is buffered, even a partial chunk (idle / shutdown).
    pub fn flush(&mut self) {
        if self.chunk.is_empty() {
            return;
        }
        let full = std::mem::replace(&mut self.chunk, Vec::with_capacity(CHUNK_FLOWS));
        if let Some(tx) = &self.tx
            && tx.send(full).is_err()
        {
            // The receiver is gone only if the encoder thread panicked.
            // Continuing would silently discard every flow from here on.
            eprintln!("Encoder thread has died; exiting");
            std::process::exit(1);
        }
    }

    /// Flush, close the channel, and wait for the encoder to write
    /// everything out.
    pub fn drain(mut self) {
        self.flush();
        self.tx.take();
        if let Some(handle) = self.handle.take()
            && handle.join().is_err()
        {
            eprintln!("Encoder thread panicked; output may be incomplete");
        }
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
