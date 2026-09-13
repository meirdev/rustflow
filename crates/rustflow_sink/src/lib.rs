//! Output sinks for `rustflow collect`: encoders turn flows into bytes,
//! destinations say where the bytes go, and the rotating sink opens and
//! closes files on an interval.

pub mod encoder;
pub mod enriched;
pub mod pipeline;
pub mod sink;

pub use encoder::{Csv, Discard, FlowEncoder, Ndjson, Parquet, Protobuf, RawEncoder};
pub use enriched::Enriched;
pub use pipeline::{FLUSH_INTERVAL, encoder_loop};
pub use sink::{FlowSink, Format, OutputMetrics, RawSink, SinkConfig, build, build_raw};
