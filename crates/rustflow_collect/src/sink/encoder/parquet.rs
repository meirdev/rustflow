use std::io;
use std::sync::Arc;

use arrow_schema::{DataType, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding};
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;
use rustflow_core::common::common_flow::CommonFlow;

use super::columns::{BATCH_ROWS, Columns};
use super::{Encoder, Writer};
use crate::enrich::Enriched;

/// Nearly every value is unique here, so a dictionary only costs time and
/// delta encoding compresses far better.
const HIGH_CARDINALITY: &[&str] = &[
    "time_received_ns",
    "time_flow_start_ns",
    "time_flow_end_ns",
    "sequence_num",
    "bytes",
    "packets",
    "fragment_id",
    "ipv6_flow_label",
    "src_port",
];

/// Snappy-compressed Apache Parquet. Rows accumulate in per-column
/// builders and go to the writer every `BATCH_ROWS`; the footer is written
/// by `finish`, so the file is unreadable until then.
pub struct Parquet {
    writer: ArrowWriter<Writer>,
    columns: Columns,
    batch_rows: usize,
    finished: bool,
}

/// Statistics only on the timestamp columns: readers prune row groups of
/// a time-ordered file by time range, never by port or counter.
fn writer_properties(schema: &Schema) -> WriterProperties {
    let mut props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_writer_version(WriterVersion::PARQUET_2_0);
    for column in HIGH_CARDINALITY {
        props = props
            .set_column_dictionary_enabled(ColumnPath::from(*column), false)
            .set_column_encoding(ColumnPath::from(*column), Encoding::DELTA_BINARY_PACKED);
    }
    for field in schema.fields() {
        if !matches!(field.data_type(), DataType::Timestamp(..)) {
            props = props.set_column_statistics_enabled(
                ColumnPath::from(field.name().as_str()),
                EnabledStatistics::None,
            );
        }
    }
    props.build()
}

impl Parquet {
    /// `open` with `BATCH_ROWS`; smaller batches make row-group behaviour
    /// testable.
    pub fn open_with_batch_rows(
        out: Writer,
        enriched_fields: &[String],
        batch_rows: usize,
    ) -> io::Result<Self> {
        let columns = Columns::new(enriched_fields);
        let props = writer_properties(columns.schema());
        let writer = ArrowWriter::try_new(out, Arc::clone(columns.schema()), Some(props))
            .map_err(io::Error::other)?;

        Ok(Self {
            writer,
            columns,
            batch_rows: batch_rows.max(1),
            finished: false,
        })
    }

    fn flush_batch(&mut self) -> io::Result<()> {
        let rows = self.columns.rows();

        let Some(batch) = self.columns.take_batch()? else {
            return Ok(());
        };

        self.writer
            .write(&batch)
            .map_err(|e| io::Error::other(format!("row group of {rows} rows lost: {e}")))
    }

    /// The footer goes out even when the last row group cannot be written:
    /// the row groups already on disk stay readable, and that partial batch
    /// is lost either way.
    fn write_footer(&mut self) -> io::Result<()> {
        self.finished = true;
        let flushed = self.flush_batch();
        let closed = self.writer.finish().map(drop).map_err(io::Error::other);
        match (flushed, closed) {
            (Err(flush), Err(close)) => Err(io::Error::new(
                flush.kind(),
                format!("{flush}; footer: {close}"),
            )),
            (flushed, closed) => flushed.and(closed),
        }
    }
}

/// A panic on the encoder thread still leaves a readable file.
impl Drop for Parquet {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.write_footer();
        }
    }
}

impl Parquet {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        Self::open_with_batch_rows(out, enriched_fields, BATCH_ROWS)
    }
}

impl Encoder for Parquet {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.columns.append(flow, enriched);
        if self.columns.rows() >= self.batch_rows {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Row groups flush themselves; nothing to push mid-stream.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.write_footer()
    }
}
