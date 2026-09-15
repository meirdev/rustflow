use std::fmt::Write as _;
use std::io;
use std::sync::Arc;

use arrow_array::builder::{PrimitiveBuilder, StringBuilder, TimestampNanosecondBuilder};
use arrow_array::types::{UInt8Type, UInt16Type, UInt32Type, UInt64Type};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding};
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::{Encoder, Writer};
use crate::enrich::Enriched;

const BATCH_ROWS: usize = 32_768;

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

macro_rules! builder {
    (FlowType) => { StringBuilder };
    (Timestamp) => { TimestampNanosecondBuilder };
    (U8) => { PrimitiveBuilder<UInt8Type> };
    (U16) => { PrimitiveBuilder<UInt16Type> };
    (U32) => { PrimitiveBuilder<UInt32Type> };
    (U64) => { PrimitiveBuilder<UInt64Type> };
    (Ip) => { StringBuilder };
    (Mac) => { StringBuilder };
}

macro_rules! new_builder {
    (Timestamp) => {
        TimestampNanosecondBuilder::new().with_timezone("UTC")
    };
    ($kind:ident) => {
        <builder!($kind)>::new()
    };
}

macro_rules! data_type {
    (FlowType) => {
        DataType::Utf8
    };
    (Timestamp) => {
        DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
    };
    (U8) => {
        DataType::UInt8
    };
    (U16) => {
        DataType::UInt16
    };
    (U32) => {
        DataType::UInt32
    };
    (U64) => {
        DataType::UInt64
    };
    (Ip) => {
        DataType::Utf8
    };
    (Mac) => {
        DataType::Utf8
    };
}

macro_rules! nullable {
    (required) => {
        false
    };
    (optional) => {
        true
    };
}

macro_rules! append {
    ($b:expr, FlowType required, $v:expr) => {
        append_text($b, $v)
    };
    ($b:expr, Ip optional, $v:expr) => {
        append_text_option($b, $v)
    };
    ($b:expr, Mac optional, $v:expr) => {
        append_text_option($b, $v)
    };
    ($b:expr, $kind:ident optional, $v:expr) => {
        $b.append_option($v)
    };
    ($b:expr, $kind:ident required, $v:expr) => {
        $b.append_value($v)
    };
}

/// `StringBuilder` implements `fmt::Write`; the empty `append_value` closes
/// the value written so far.
fn append_text(b: &mut StringBuilder, v: impl std::fmt::Display) {
    let _ = write!(b, "{v}");
    b.append_value("");
}

fn append_text_option(b: &mut StringBuilder, v: Option<impl std::fmt::Display>) {
    match v {
        Some(v) => append_text(b, v),
        None => b.append_null(),
    }
}

macro_rules! flow_columns {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        struct FlowColumns {
            $( $name: builder!($kind), )*
        }

        impl FlowColumns {
            fn new() -> Self {
                Self { $( $name: new_builder!($kind), )* }
            }

            fn fields() -> Vec<Field> {
                vec![ $( Field::new(stringify!($name), data_type!($kind), nullable!($presence)), )* ]
            }

            fn append(&mut self, flow: &CommonFlow) {
                let CommonFlow { $( $name, )* } = flow;
                $( append!(&mut self.$name, $kind $presence, *$name); )*
            }

            fn finish(&mut self) -> Vec<ArrayRef> {
                vec![ $( Arc::new(self.$name.finish()) as ArrayRef, )* ]
            }
        }
    };
}
for_each_flow_field!(flow_columns);

/// Snappy-compressed Apache Parquet. Rows accumulate in per-column
/// builders and go to the writer every `BATCH_ROWS`; the footer is written
/// by `finish`, so the file is unreadable until then.
pub struct Parquet {
    writer: ArrowWriter<Writer>,
    schema: Arc<Schema>,
    flow: FlowColumns,
    enrichment: Vec<StringBuilder>,
    rows: usize,
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
        let mut fields = FlowColumns::fields();
        for name in enriched_fields {
            fields.push(Field::new(name, DataType::Utf8, true));
        }
        let schema = Arc::new(Schema::new(fields));
        let props = writer_properties(&schema);
        let writer = ArrowWriter::try_new(out, Arc::clone(&schema), Some(props))
            .map_err(io::Error::other)?;
        Ok(Self {
            writer,
            schema,
            flow: FlowColumns::new(),
            enrichment: enriched_fields
                .iter()
                .map(|_| StringBuilder::new())
                .collect(),
            rows: 0,
            batch_rows: batch_rows.max(1),
            finished: false,
        })
    }

    fn flush_batch(&mut self) -> io::Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        let mut columns = self.flow.finish();
        columns.extend(
            self.enrichment
                .iter_mut()
                .map(|b| Arc::new(b.finish()) as ArrayRef),
        );
        let rows = std::mem::take(&mut self.rows);
        let batch =
            RecordBatch::try_new(Arc::clone(&self.schema), columns).map_err(io::Error::other)?;
        self.writer
            .write(&batch)
            .map_err(|e| io::Error::other(format!("row group of {rows} rows lost: {e}")))
    }

    fn write_footer(&mut self) -> io::Result<()> {
        self.finished = true;
        self.flush_batch()?;
        self.writer.finish().map(drop).map_err(io::Error::other)
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
        self.flow.append(flow);
        for (builder, value) in self.enrichment.iter_mut().zip(enriched.iter()) {
            builder.append_option(value);
        }
        self.rows += 1;
        if self.rows >= self.batch_rows {
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
