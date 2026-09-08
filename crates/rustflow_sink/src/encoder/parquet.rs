use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;

use arrow_array::builder::{PrimitiveBuilder, StringBuilder, TimestampNanosecondBuilder};
use arrow_array::types::{ArrowPrimitiveType, UInt8Type, UInt16Type, UInt32Type, UInt64Type};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use macaddr::MacAddr6;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding};
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

use super::text::{AddrText, flow_type_name};
use super::{FlowEncoder, Output};
use crate::flow::Enriched;
use crate::flow::fields::for_each_flow_field;

/// Rows buffered in the Arrow builders before a batch is handed to the
/// writer. Large enough to amortize the per-batch setup across all ~40
/// columns.
const BATCH_ROWS: usize = 32_768;

/// Columns where nearly every value is unique: a dictionary is pure
/// overhead there, and delta encoding compresses monotonic timestamps and
/// counters far better. Measured: 20 % less time and 25 % smaller files
/// than the defaults on realistic data.
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

/// What the column list needs to know about one kind of column. Static
/// dispatch only: every `append` inlines to a plain builder call.
trait ColumnKind {
    type Builder;
    type Value: Copy;
    const NULLABLE: bool;
    fn data_type() -> DataType;
    fn builder() -> Self::Builder;
    fn append(builder: &mut Self::Builder, value: Self::Value);
    fn finish(builder: &mut Self::Builder) -> ArrayRef;
}

/// A nullable integer column of Arrow type `T`.
struct Nullable<T>(PhantomData<T>);

impl<T: ArrowPrimitiveType> ColumnKind for Nullable<T> {
    type Builder = PrimitiveBuilder<T>;
    type Value = Option<T::Native>;
    const NULLABLE: bool = true;
    fn data_type() -> DataType {
        T::DATA_TYPE
    }
    fn builder() -> Self::Builder {
        PrimitiveBuilder::new()
    }
    fn append(b: &mut Self::Builder, v: Self::Value) {
        b.append_option(v)
    }
    fn finish(b: &mut Self::Builder) -> ArrayRef {
        Arc::new(b.finish())
    }
}

/// A non-nullable integer column of Arrow type `T`.
struct Required<T>(PhantomData<T>);

impl<T: ArrowPrimitiveType> ColumnKind for Required<T> {
    type Builder = PrimitiveBuilder<T>;
    type Value = T::Native;
    const NULLABLE: bool = false;
    fn data_type() -> DataType {
        T::DATA_TYPE
    }
    fn builder() -> Self::Builder {
        PrimitiveBuilder::new()
    }
    fn append(b: &mut Self::Builder, v: Self::Value) {
        b.append_value(v)
    }
    fn finish(b: &mut Self::Builder) -> ArrayRef {
        Arc::new(b.finish())
    }
}

/// Nanoseconds since the Unix epoch, typed as a UTC timestamp.
struct Timestamp;

impl ColumnKind for Timestamp {
    type Builder = TimestampNanosecondBuilder;
    type Value = Option<i64>;
    const NULLABLE: bool = true;
    fn data_type() -> DataType {
        DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
    }
    fn builder() -> Self::Builder {
        TimestampNanosecondBuilder::new().with_timezone("UTC")
    }
    fn append(b: &mut Self::Builder, v: Self::Value) {
        b.append_option(v)
    }
    fn finish(b: &mut Self::Builder) -> ArrayRef {
        Arc::new(b.finish())
    }
}

/// A text column, written without `core::fmt` (see `text.rs`).
macro_rules! text_kind {
    ($kind:ident, $value:ty, $nullable:expr, |$b:ident, $v:ident| $append:expr) => {
        struct $kind;
        impl ColumnKind for $kind {
            type Builder = StringBuilder;
            type Value = $value;
            const NULLABLE: bool = $nullable;
            fn data_type() -> DataType {
                DataType::Utf8
            }
            fn builder() -> StringBuilder {
                StringBuilder::new()
            }
            fn append($b: &mut StringBuilder, $v: $value) {
                $append
            }
            fn finish(b: &mut StringBuilder) -> ArrayRef {
                Arc::new(b.finish())
            }
        }
    };
}

text_kind!(FlowTypeName, FlowType, false, |b, v| b
    .append_value(flow_type_name(v)));
text_kind!(Ip, Option<IpAddr>, true, |b, v| match v {
    Some(v) => b.append_value(AddrText::ip(v).as_str()),
    None => b.append_null(),
});
text_kind!(Mac, Option<MacAddr6>, true, |b, v| match v {
    Some(v) => b.append_value(AddrText::mac(v).as_str()),
    None => b.append_null(),
});

/// How each kind and presence in the shared field list is stored here.
/// This is the one place that decides "an IP address is a Utf8 column".
macro_rules! column_kind {
    (FlowType required) => { FlowTypeName };
    (Timestamp optional) => { Timestamp };
    (U8 optional) => { Nullable<UInt8Type> };
    (U16 optional) => { Nullable<UInt16Type> };
    (U32 optional) => { Nullable<UInt32Type> };
    (U32 required) => { Required<UInt32Type> };
    (U64 required) => { Required<UInt64Type> };
    (Ip optional) => { Ip };
    (Mac optional) => { Mac };
}

/// One typed builder per flow column, expanded from the shared field list.
///
/// Typed builders rather than the `fields::visit` walk: measured 14 %
/// faster on this encoder, because every append is a direct builder call
/// with nothing in between. The destructure in `append` has no `..`, so a
/// field added to `CommonFlow` fails to compile until it is in the list.
macro_rules! flow_columns {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        struct FlowColumns {
            $( $name: <column_kind!($kind $presence) as ColumnKind>::Builder, )*
        }

        impl FlowColumns {
            fn new() -> Self {
                Self { $( $name: <column_kind!($kind $presence) as ColumnKind>::builder(), )* }
            }

            fn fields() -> Vec<Field> {
                vec![ $( Field::new(
                    stringify!($name),
                    <column_kind!($kind $presence) as ColumnKind>::data_type(),
                    <column_kind!($kind $presence) as ColumnKind>::NULLABLE,
                ), )* ]
            }

            fn append(&mut self, flow: &CommonFlow) {
                let CommonFlow { $( $name, )* } = flow;
                $( <column_kind!($kind $presence) as ColumnKind>::append(&mut self.$name, *$name); )*
            }

            fn finish(&mut self) -> Vec<ArrayRef> {
                vec![ $( <column_kind!($kind $presence) as ColumnKind>::finish(&mut self.$name), )* ]
            }
        }
    };
}
for_each_flow_field!(flow_columns);

/// Snappy-compressed Apache Parquet.
///
/// Each flow is appended field-by-field into typed per-column Arrow
/// builders; every `BATCH_ROWS` rows the builders are drained into a
/// record batch for the writer, which manages pages and row groups. The
/// footer is only written by `finish`, so the file is unreadable until the
/// encoder is finished.
pub struct Parquet {
    writer: ArrowWriter<Output>,
    schema: Arc<Schema>,
    flow: FlowColumns,
    /// One text column per enrichment field, after the flow columns.
    enrichment: Vec<StringBuilder>,
    rows: usize,
    batch_rows: usize,
}

/// Writer settings, chosen by measurement (see `SINK_DESIGN.md` §14):
///
/// - Snappy: cheap to encode, well supported.
/// - High-cardinality timestamps and counters: no dictionary, delta binary
///   packed (needs the v2 writer). Smaller and faster than the default.
/// - Statistics only on the timestamp columns. Time-range pruning is what
///   readers use on flow data; min/max of ports, counters, or address
///   strings never prunes a row group of a time-ordered file, and costs a
///   comparison per value.
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
    fn open_with_batch_rows(
        out: Output,
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
        })
    }

    /// Drain the builders into one record batch for the writer.
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
        self.rows = 0;
        let batch =
            RecordBatch::try_new(Arc::clone(&self.schema), columns).map_err(io::Error::other)?;
        self.writer.write(&batch).map_err(io::Error::other)
    }
}

impl FlowEncoder for Parquet {
    const EXTENSION: &'static str = "parquet";

    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self> {
        Self::open_with_batch_rows(out, enriched_fields, BATCH_ROWS)
    }

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

    /// Row groups flush themselves; there is nothing to push mid-stream.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.flush_batch()?;
        self.writer.close().map(drop).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests;
