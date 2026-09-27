use std::fmt::Write as _;
use std::io;
use std::sync::Arc;

use arrow_array::builder::{PrimitiveBuilder, StringBuilder, TimestampNanosecondBuilder};
use arrow_array::types::{UInt8Type, UInt16Type, UInt32Type, UInt64Type};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use crate::enrich::Enriched;

/// Rows per record batch when nothing flushes earlier.
pub const BATCH_ROWS: usize = 32_768;

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

/// Rows accumulating in per-column builders until taken as a batch.
pub struct Columns {
    schema: Arc<Schema>,
    flow: FlowColumns,
    enrichment: Vec<StringBuilder>,
    rows: usize,
}

impl Columns {
    pub fn new(enriched_fields: &[String]) -> Self {
        let mut fields = FlowColumns::fields();
        for name in enriched_fields {
            fields.push(Field::new(name, DataType::Utf8, true));
        }
        Self {
            schema: Arc::new(Schema::new(fields)),
            flow: FlowColumns::new(),
            enrichment: enriched_fields
                .iter()
                .map(|_| StringBuilder::new())
                .collect(),
            rows: 0,
        }
    }

    pub fn schema(&self) -> &Arc<Schema> {
        &self.schema
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn append(&mut self, flow: &CommonFlow, enriched: &Enriched) {
        self.flow.append(flow);
        for (builder, value) in self.enrichment.iter_mut().zip(enriched.iter()) {
            builder.append_option(value.as_deref());
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
        let mut columns = self.flow.finish();
        columns.extend(
            self.enrichment
                .iter_mut()
                .map(|b| Arc::new(b.finish()) as ArrayRef),
        );
        RecordBatch::try_new(Arc::clone(&self.schema), columns)
            .map(Some)
            .map_err(io::Error::other)
    }
}
