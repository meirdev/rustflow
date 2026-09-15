mod csv;
mod discard;
mod ndjson;
mod parquet;
mod protobuf;

use std::io::{self, Write};

pub use discard::Discard;
pub use ndjson::Ndjson;
pub use protobuf::{FlowMessage, Protobuf};
use rustflow_core::common::common_flow::CommonFlow;

pub use self::csv::Csv;
pub use self::parquet::Parquet;
use crate::enrich::Enriched;

/// Records are not flushed individually; this bounds how often the
/// encoder calls into the kernel.
pub(crate) const WRITE_BUFFER_BYTES: usize = 256 * 1024;

pub type Writer = Box<dyn Write + Send>;

/// Turns records into bytes in one format. Knows nothing about files,
/// rotation, or threads. Every encoder's `open` writes its header right
/// away, so a rotated file is well-formed even when empty.
pub trait Encoder: Send {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    /// Records the ingest thread already serialized as JSON lines
    /// (`--format raw`); only NDJSON and discard take them.
    fn write_raw(&mut self, _lines: &[u8]) -> io::Result<()> {
        Err(io::Error::other(
            "raw records need --serialization ndjson or discard",
        ))
    }

    fn flush(&mut self) -> io::Result<()>;

    /// Ends the stream (Parquet footer).
    fn finish(&mut self) -> io::Result<()>;
}
