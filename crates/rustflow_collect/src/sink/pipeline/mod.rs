pub mod encoder;
pub mod errors;
pub mod raw;
pub mod timer;

use std::io;
use std::time::Duration;

pub use encoder::{CHUNK_FLUSH_TIMEOUT, Encoder, encoder_loop};
pub use errors::SinkErrors;
pub use raw::RawOutput;
pub use timer::FlushTimer;

use crate::enrich::EnrichmentEngine;
use crate::sink::{self, OutputFormat, OutputMetrics, SinkConfig};

/// How often buffered output is pushed out when flows trickle in too slowly
/// to fill the write buffer.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Raw packets are written on the ingest thread; common flows cross to the
/// encoder thread, which converts them to the destination format.
pub enum Output {
    Raw(Box<RawOutput>),
    Common(Encoder),
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
                Output::Common(Encoder::spawn(sink, enrichment, metrics.clone()))
            }
        })
    }

    /// Nothing arrived for a while: hand over a partial chunk, or flush.
    pub fn idle(&mut self) {
        match self {
            Output::Raw(raw) => raw.idle(),
            Output::Common(encoder) => encoder.flush(),
        }
    }

    /// Write everything out and close the output.
    pub fn finish(self) -> io::Result<()> {
        match self {
            Output::Raw(raw) => raw.finish(),
            Output::Common(encoder) => encoder.drain(),
        }
    }
}
