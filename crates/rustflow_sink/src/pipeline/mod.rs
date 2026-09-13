pub mod errors;
pub mod timer;

use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use chrono::Utc;
use rustflow_core::common::common_flow::CommonFlow;

pub use errors::SinkErrors;
pub use timer::FlushTimer;

use crate::enriched::Enriched;
use crate::sink::{FlowSink, OutputMetrics};

/// How often buffered output is pushed out when flows trickle in too slowly
/// to fill the write buffer.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// The encoder thread's body: drains chunks of flows until every sender is
/// gone, then finishes the output. Rotation is checked per chunk and on the
/// flush deadline, so an idle pipeline still rotates its empty window.
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
