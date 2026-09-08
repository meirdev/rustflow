//! Layer 1: turning one flow into bytes, one file per format.

mod csv;
mod discard;
mod ndjson;
mod parquet;
mod protobuf;
pub mod text;

use std::io::{self, Write};

use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use crate::flow::Enriched;

pub use self::csv::Csv;
pub use self::parquet::Parquet;
pub use discard::Discard;
pub use ndjson::Ndjson;
pub use protobuf::Protobuf;
pub use text::{AddrText, flow_type_name};

/// Buffer size for the text encoders. Records are not flushed individually,
/// so this is what bounds how often the collector calls into the kernel.
pub(crate) const WRITE_BUFFER_BYTES: usize = 256 * 1024;

/// The byte stream an encoder writes into.
pub type Output = Box<dyn Write + Send>;

/// Turns flows into bytes in one format. Knows nothing about files,
/// rotation, or threads.
pub trait FlowEncoder: Send + Sized {
    /// File extension used by the partitioned tree (`flows-….<EXTENSION>`).
    const EXTENSION: &'static str;

    /// Start a new stream. Writes any header (CSV header row, Parquet
    /// schema) now, so a rotated file is well-formed even when empty.
    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self>;

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    /// Push buffered bytes to the destination without ending the stream.
    fn flush(&mut self) -> io::Result<()>;

    /// End the stream (Parquet footer). Consumes `self`, so "write after
    /// finish" is a compile error and needs no runtime guard.
    fn finish(self) -> io::Result<()>;
}

/// An encoder that can also carry an arbitrary serializable record, which
/// is what `--format raw` writes. Only NDJSON and Discard qualify.
pub trait RawEncoder: FlowEncoder {
    fn write_value<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()>;
}
