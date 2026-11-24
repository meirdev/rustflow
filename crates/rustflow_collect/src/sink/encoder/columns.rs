use std::io;
use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, PrimitiveBuilder, StringBuilder, TimestampNanosecondBuilder,
};
use arrow_array::types::{Float64Type, Int64Type, UInt8Type, UInt16Type, UInt32Type, UInt64Type};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};
use rustflow_core::common_flow::CommonFlow;

use crate::enrich::Enriched;
use crate::field::{Kind, Scalar};
use crate::schema::{Column, Schema};

/// Rows per record batch when nothing flushes earlier.
pub const BATCH_ROWS: usize = 32_768;

const UTC: &str = "UTC";

fn timestamp_type() -> DataType {
    DataType::Timestamp(TimeUnit::Nanosecond, Some(UTC.into()))
}

/// The values of one column, until taken as an array.
enum Builder {
    U8(PrimitiveBuilder<UInt8Type>),
    U16(PrimitiveBuilder<UInt16Type>),
    U32(PrimitiveBuilder<UInt32Type>),
    U64(PrimitiveBuilder<UInt64Type>),
    I64(PrimitiveBuilder<Int64Type>),
    F64(PrimitiveBuilder<Float64Type>),
    Boolean(BooleanBuilder),
    Timestamp(TimestampNanosecondBuilder),
    Utf8(StringBuilder),
}

impl Builder {
    fn new(kind: Kind) -> (DataType, Self) {
        match kind {
            Kind::U8 => (DataType::UInt8, Self::U8(PrimitiveBuilder::new())),
            Kind::U16 => (DataType::UInt16, Self::U16(PrimitiveBuilder::new())),
            Kind::U32 => (DataType::UInt32, Self::U32(PrimitiveBuilder::new())),
            Kind::U64 => (DataType::UInt64, Self::U64(PrimitiveBuilder::new())),
            Kind::I64 => (DataType::Int64, Self::I64(PrimitiveBuilder::new())),
            Kind::F64 => (DataType::Float64, Self::F64(PrimitiveBuilder::new())),
            Kind::Boolean => (DataType::Boolean, Self::Boolean(BooleanBuilder::new())),
            Kind::Timestamp => (
                timestamp_type(),
                Self::Timestamp(TimestampNanosecondBuilder::new().with_timezone(UTC)),
            ),
            Kind::Text | Kind::FlowType | Kind::Address | Kind::Mac | Kind::Octets => {
                (DataType::Utf8, Self::Utf8(StringBuilder::new()))
            }
        }
    }

    /// `value` as its column holds it; null when there is none, or it is
    /// not of the column's kind.
    fn append(&mut self, text: &mut Vec<u8>, value: Option<Scalar<'_>>) {
        match (self, value) {
            // A column narrower than 64 bits is of a flow field that wide.
            (Self::U8(b), Some(Scalar::Unsigned(v))) => b.append_value(v as u8),
            (Self::U16(b), Some(Scalar::Unsigned(v))) => b.append_value(v as u16),
            (Self::U32(b), Some(Scalar::Unsigned(v))) => b.append_value(v as u32),
            (Self::U64(b), Some(Scalar::Unsigned(v))) => b.append_value(v),
            (Self::I64(b), Some(Scalar::Signed(v))) => b.append_value(v),
            (Self::F64(b), Some(Scalar::Float(v))) => b.append_value(v),
            (Self::Boolean(b), Some(Scalar::Boolean(v))) => b.append_value(v),
            (Self::Timestamp(b), Some(Scalar::Timestamp(v))) => b.append_value(v),
            (Self::Utf8(b), Some(Scalar::String(v))) => b.append_value(v),
            (Self::Utf8(b), Some(value)) => {
                text.clear();
                value.write_text(text);
                b.append_value(std::str::from_utf8(text).expect("text is ASCII"));
            }
            (Self::U8(b), _) => b.append_null(),
            (Self::U16(b), _) => b.append_null(),
            (Self::U32(b), _) => b.append_null(),
            (Self::U64(b), _) => b.append_null(),
            (Self::I64(b), _) => b.append_null(),
            (Self::F64(b), _) => b.append_null(),
            (Self::Boolean(b), _) => b.append_null(),
            (Self::Timestamp(b), _) => b.append_null(),
            (Self::Utf8(b), None) => b.append_null(),
        }
    }

    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::U8(b) => Arc::new(b.finish()),
            Self::U16(b) => Arc::new(b.finish()),
            Self::U32(b) => Arc::new(b.finish()),
            Self::U64(b) => Arc::new(b.finish()),
            Self::I64(b) => Arc::new(b.finish()),
            Self::F64(b) => Arc::new(b.finish()),
            Self::Boolean(b) => Arc::new(b.finish()),
            Self::Timestamp(b) => Arc::new(b.finish()),
            Self::Utf8(b) => Arc::new(b.finish()),
        }
    }
}

/// Rows accumulating in per-column builders until taken as a batch.
pub struct Columns {
    schema: Arc<ArrowSchema>,
    columns: Vec<(Column, Builder)>,
    text: Vec<u8>,
    rows: usize,
}

impl Columns {
    pub fn new(schema: &Schema) -> Self {
        let mut fields = Vec::new();
        let mut columns = Vec::new();
        for column in schema.columns() {
            let (data_type, builder) = Builder::new(column.kind);
            fields.push(Field::new(&column.name, data_type, !column.required));
            columns.push((column.clone(), builder));
        }
        Self {
            schema: Arc::new(ArrowSchema::new(fields)),
            columns,
            text: Vec::new(),
            rows: 0,
        }
    }

    pub fn schema(&self) -> &Arc<ArrowSchema> {
        &self.schema
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn append(&mut self, flow: &CommonFlow, enriched: &Enriched) {
        for (column, builder) in &mut self.columns {
            builder.append(&mut self.text, column.value(flow, enriched));
        }
        self.rows += 1;
    }

    /// The rows appended so far as one batch, leaving the builders empty;
    /// `None` when there are none.
    pub fn take_batch(&mut self) -> io::Result<Option<RecordBatch>> {
        if self.rows == 0 {
            return Ok(None);
        }
        self.rows = 0;
        let columns = (self.columns.iter_mut())
            .map(|(_, builder)| builder.finish())
            .collect();
        RecordBatch::try_new(Arc::clone(&self.schema), columns)
            .map(Some)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use arrow_array::cast::AsArray;
    use arrow_array::types::TimestampNanosecondType;
    use rustflow_core::common_flow::FlowType;
    use rustflow_core::value::Value;

    use super::*;
    use crate::field;

    #[test]
    fn added_columns_are_typed_by_their_kind() {
        let field = |name: &str, kind| field::Field {
            name: name.into(),
            kind,
            number: None,
        };
        let schema = Schema::new(
            &[
                field("count", Kind::U64),
                field("start", Kind::Timestamp),
                field("host", Kind::Text),
            ],
            &[field("site", Kind::Text), field("asn", Kind::U64)],
        )
        .unwrap();
        let mut columns = Columns::new(&schema);
        let mut flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 0);
        flow.extra = vec![
            Some(Value::Unsigned32(7)),
            Some(Value::DateTimeSeconds(2)),
            None,
        ]
        .into();
        let enriched = vec![
            Some(field::Value::Text("a".into())),
            Some(field::Value::Unsigned(64512)),
        ];
        columns.append(&flow, &enriched);

        let batch = columns.take_batch().unwrap().unwrap();
        let types: Vec<_> = batch.schema().fields()[CommonFlow::FIELD_NAMES.len()..]
            .iter()
            .map(|field| (field.name().clone(), field.data_type().clone()))
            .collect();
        assert_eq!(
            types,
            [
                ("count".to_string(), DataType::UInt64),
                ("start".to_string(), timestamp_type()),
                ("host".to_string(), DataType::Utf8),
                ("site".to_string(), DataType::Utf8),
                ("asn".to_string(), DataType::UInt64),
            ]
        );
        let column = |name| batch.column_by_name(name).unwrap();
        assert_eq!(column("count").as_primitive::<UInt64Type>().value(0), 7);
        let start = column("start").as_primitive::<TimestampNanosecondType>();
        assert_eq!(start.value(0), 2_000_000_000);
        assert!(column("host").is_null(0));
        assert_eq!(column("site").as_string::<i32>().value(0), "a");
        assert_eq!(column("asn").as_primitive::<UInt64Type>().value(0), 64512);
    }
}
