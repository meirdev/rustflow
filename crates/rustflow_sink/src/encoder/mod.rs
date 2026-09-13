mod csv;
mod discard;
mod ndjson;
mod parquet;
mod protobuf;

use std::io::{self, Write};

use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use crate::enriched::Enriched;

pub use self::csv::Csv;
pub use self::parquet::Parquet;
pub use discard::Discard;
pub use ndjson::Ndjson;
pub use protobuf::{FlowMessage, Protobuf};

/// Records are not flushed individually; this bounds how often the
/// encoder calls into the kernel.
pub(crate) const WRITE_BUFFER_BYTES: usize = 256 * 1024;

pub type Output = Box<dyn Write + Send>;

/// Turns flows into bytes in one format. Knows nothing about files,
/// rotation, or threads.
pub trait FlowEncoder: Send + Sized {
    /// File extension in the partitioned tree.
    const EXTENSION: &'static str;

    /// Writes any header now, so a rotated file is well-formed even when empty.
    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self>;

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    fn flush(&mut self) -> io::Result<()>;

    /// Ends the stream (Parquet footer). Consumes `self`, so writing after
    /// finish is a compile error.
    fn finish(self) -> io::Result<()>;
}

/// An encoder that can also carry an arbitrary serializable record, which
/// is what `--format raw` writes.
pub trait RawEncoder: FlowEncoder {
    fn write_value<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()>;
}
