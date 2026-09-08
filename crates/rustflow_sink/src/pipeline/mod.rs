//! The encoder thread: owns the sink, drains decoded flows, flushes on a
//! deadline, and reports errors once per state change.

pub mod errors;
pub mod timer;

use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use chrono::Utc;
use rustflow_core::common::common_flow::CommonFlow;

pub use errors::SinkErrors;
pub use timer::FlushTimer;

use crate::flow::Enriched;
use crate::sink::{FlowSink, OutputMetrics};

/// How often buffered output is pushed to the destination when flows
/// trickle in too slowly to fill the write buffer.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// The encoder thread's body: owns the sink, drains chunks of decoded flows
/// until every sender is gone, then finishes the output.
///
/// `enrich` fills the reusable [`Enriched`] for each flow; the sink crate
/// does not know the enrichment engine.
///
/// Rotation is checked once per chunk, not once per flow. Flushing runs on
/// the [`FlushTimer`] deadline, checked after every chunk as well as on
/// timeout, so a busy pipeline flushes on cadence and an idle one still
/// rotates its empty window on time.
pub fn encoder_loop(
    rx: Receiver<Vec<CommonFlow>>,
    mut sink: Box<dyn FlowSink>,
    enriched_field_count: usize,
    mut enrich: impl FnMut(&CommonFlow, &mut Enriched),
    metrics: &OutputMetrics,
) -> io::Result<()> {
    let mut enriched = Enriched::new(enriched_field_count);
    let mut errors = SinkErrors::new(metrics);
    let mut timer = FlushTimer::new(FLUSH_INTERVAL);

    loop {
        match rx.recv_timeout(timer.remaining()) {
            Ok(flows) => {
                errors.rotate(sink.rotate_if_due(Utc::now()));
                for flow in &flows {
                    enriched.clear();
                    enrich(flow, &mut enriched);
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::encoder::Ndjson;
    use crate::sink::Destination;
    use crate::sink::RotatingSink;
    use crate::test_support::sample_flow;

    #[test]
    fn drains_every_chunk_then_finishes() {
        let path = std::env::temp_dir().join("rustflow_sink_pipeline_test.ndjson");
        let metrics = OutputMetrics::new();
        let sink: Box<dyn FlowSink> = Box::new(
            RotatingSink::<Ndjson>::open(
                Destination::File(path.clone()),
                vec!["src_asn".into()],
                metrics.clone(),
            )
            .unwrap(),
        );

        let (tx, rx) = mpsc::sync_channel(4);
        let producer = std::thread::spawn(move || {
            tx.send(vec![sample_flow(), sample_flow()]).unwrap();
            tx.send(vec![sample_flow()]).unwrap();
            // dropping `tx` closes the channel
        });

        let enrich = |_: &CommonFlow, out: &mut Enriched| out.set(0, "13335");
        encoder_loop(rx, sink, 1, enrich, &metrics).unwrap();
        producer.join().unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.lines().all(|l| l.contains("\"src_asn\":\"13335\"")));
        assert_eq!(metrics.flows.get(), 3);

        std::fs::remove_file(&path).ok();
    }
}
