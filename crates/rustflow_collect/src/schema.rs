//! The columns of the output: the flow's fields, then the fields added to
//! it. Every encoder writes the columns of one [`Schema`], each the same
//! way, and an enrichment lookup takes its keys from them.

use std::collections::HashSet;

use anyhow::{Result, bail};
use rustflow_core::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use crate::field::{Field, Kind, Scalar, Value};

/// The protobuf field numbers below this are the flow's own fields, now
/// or later.
const FIRST_ADDED_NUMBER: u32 = 1000;
const MAX_NUMBER: u32 = (1 << 29) - 1;
/// Protobuf keeps these for its implementation.
const RESERVED_NUMBERS: std::ops::RangeInclusive<u32> = 19_000..=19_999;

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub kind: Kind,
    /// Every flow has a value for it.
    pub required: bool,
    /// Its protobuf field number.
    pub number: u32,
    source: Source,
}

#[derive(Debug, Clone, Copy)]
enum Source {
    /// A field of the flow.
    Flow(for<'a> fn(&'a CommonFlow) -> Option<Scalar<'a>>),
    /// A value of `CommonFlow::extra`, by its position.
    Extra(usize),
    /// A value the enrichment looked up, by its position in the row.
    Lookup(usize),
}

impl Column {
    /// The column's value for `flow`, if it has one; `enriched` is the
    /// row the enrichment looked up for it.
    pub fn value<'a>(
        &self,
        flow: &'a CommonFlow,
        enriched: &'a [Option<Value>],
    ) -> Option<Scalar<'a>> {
        match self.source {
            Source::Flow(field) => field(flow),
            Source::Extra(index) => Scalar::of_record(flow.extra.get(index)?, self.kind),
            Source::Lookup(index) => enriched.get(index)?.as_ref().map(Scalar::of_table),
        }
    }

    /// The position in `CommonFlow::FIELD_NAMES` of the field of the flow
    /// that the column is, if it is one.
    pub fn flow_field(&self) -> Option<usize> {
        // The flow's fields are numbered from 1 in that order.
        (!self.is_added()).then(|| self.number as usize - 1)
    }

    /// A column `--extra-field` or `--enrich` added, not one of the
    /// flow's own.
    pub fn is_added(&self) -> bool {
        !matches!(self.source, Source::Flow(_))
    }
}

macro_rules! kind {
    (Protocol) => {
        Kind::FlowType
    };
    (Timestamp) => {
        Kind::Timestamp
    };
    (U8) => {
        Kind::U8
    };
    (U16) => {
        Kind::U16
    };
    (U32) => {
        Kind::U32
    };
    (U64) => {
        Kind::U64
    };
    (Ip) => {
        Kind::Address
    };
    (Mac) => {
        Kind::Mac
    };
}

macro_rules! scalar {
    (Protocol, $value:expr) => {
        Scalar::FlowType($value)
    };
    (Timestamp, $value:expr) => {
        Scalar::Timestamp($value)
    };
    (Ip, $value:expr) => {
        Scalar::Address($value)
    };
    (Mac, $value:expr) => {
        Scalar::Mac($value)
    };
    ($unsigned:ident, $value:expr) => {
        Scalar::Unsigned($value.into())
    };
}

macro_rules! source {
    ($name:ident, $kind:ident, required) => {
        Source::Flow(|flow| Some(scalar!($kind, flow.$name)))
    };
    ($name:ident, $kind:ident, optional) => {
        Source::Flow(|flow| flow.$name.map(|value| scalar!($kind, value)))
    };
}

macro_rules! required {
    (required) => {
        true
    };
    (optional) => {
        false
    };
}

macro_rules! flow_columns {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        /// The flow's fields as columns, numbered from 1 in their order.
        fn flow_columns() -> Vec<Column> {
            let fields = [
                $( (stringify!($name), kind!($kind), required!($presence), source!($name, $kind, $presence)), )*
            ];
            let numbered = (1..).zip(fields);
            numbered
                .map(|(number, (name, kind, required, source))| Column {
                    name: name.into(),
                    kind,
                    required,
                    number,
                    source,
                })
                .collect()
        }
    };
}
for_each_flow_field!(flow_columns);

#[derive(Debug, Clone, Default)]
pub struct Schema {
    columns: Vec<Column>,
}

impl Schema {
    /// The flow's fields, then `extra`, the fields of `CommonFlow::extra`,
    /// then `enriched`, the fields of the enrichment's row. A name or a
    /// protobuf number may not be used twice; a field without a number is
    /// given the next free one.
    pub fn new(extra: &[Field], enriched: &[Field]) -> Result<Self> {
        let mut columns = flow_columns();

        let extra = extra.iter().enumerate().map(|(i, f)| (Source::Extra(i), f));
        let enriched = (enriched.iter().enumerate()).map(|(i, f)| (Source::Lookup(i), f));
        let added: Vec<_> = extra.chain(enriched).collect();

        let mut taken = HashSet::new();
        for (_, field) in &added {
            let Some(number) = field.number else { continue };
            if !(FIRST_ADDED_NUMBER..=MAX_NUMBER).contains(&number)
                || RESERVED_NUMBERS.contains(&number)
            {
                bail!(
                    "Field '{}': number {number} is not between {FIRST_ADDED_NUMBER} and \
                     {MAX_NUMBER}, or is one of the reserved {RESERVED_NUMBERS:?}",
                    field.name
                );
            }
            if !taken.insert(number) {
                bail!("Field '{}': number {number} is used twice", field.name);
            }
        }

        let mut free = (FIRST_ADDED_NUMBER..=MAX_NUMBER).filter(|n| !RESERVED_NUMBERS.contains(n));
        for (source, field) in added {
            if columns.iter().any(|column| column.name == field.name) {
                bail!("Field '{}' is already the name of a column", field.name);
            }
            let number = match field.number {
                Some(number) => number,
                None => free
                    .find(|number| !taken.contains(number))
                    .expect("there are more numbers than fields"),
            };
            columns.push(Column {
                name: field.name.clone(),
                kind: field.kind,
                required: false,
                number,
                source,
            });
        }
        Ok(Self { columns })
    }

    /// The schema of the columns `names` list, in that order.
    pub fn select(&self, names: &[String]) -> Result<Self> {
        let mut columns: Vec<Column> = Vec::new();
        for name in names {
            let Some(column) = self.column(name) else {
                bail!("Unknown field '{name}'");
            };
            if columns.iter().any(|selected| selected.name == *name) {
                bail!("Field '{name}' is selected twice");
            }
            columns.push(column.clone());
        }
        Ok(Self { columns })
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }

    /// The lines that declare the added fields in `rustflow.proto`.
    pub fn proto_lines(&self) -> impl Iterator<Item = String> {
        let added = self.columns.iter().filter(|column| column.is_added());
        added.map(
            |Column {
                 name, kind, number, ..
             }| { format!("optional {} {name} = {number};", kind.proto_type()) },
        )
    }
}

#[cfg(test)]
mod tests {
    use rustflow_core::common_flow::FlowType;
    use rustflow_core::value;

    use super::*;

    fn field(name: &str, kind: Kind, number: Option<u32>) -> Field {
        Field {
            name: name.into(),
            kind,
            number,
        }
    }

    fn names(schema: &Schema) -> Vec<&str> {
        let columns = schema.columns().iter();
        columns.map(|column| column.name.as_str()).collect()
    }

    #[test]
    fn columns_are_the_flow_then_the_added_fields() {
        let schema = Schema::new(
            &[field("vrf", Kind::U64, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();

        let flow_fields = CommonFlow::FIELD_NAMES.len();
        assert_eq!(names(&schema)[..flow_fields], *CommonFlow::FIELD_NAMES);
        assert_eq!(names(&schema)[flow_fields..], ["vrf", "site"]);
        let numbers = schema.columns().iter().map(|column| column.number);
        assert!(numbers.take(flow_fields).eq(1..=flow_fields as u32));
        let flow_type = schema.column("flow_type").unwrap();
        assert!(flow_type.required && !flow_type.is_added());
        assert!(schema.column("vrf").unwrap().is_added());
    }

    #[test]
    fn a_selection_is_the_listed_columns_in_their_order() {
        let schema = Schema::new(
            &[field("vrf", Kind::U64, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        let select = |names: &[&str]| {
            let names: Vec<_> = names.iter().map(|name| name.to_string()).collect();
            schema.select(&names)
        };

        let selected = select(&["site", "bytes", "flow_type"]).unwrap();
        assert_eq!(names(&selected), ["site", "bytes", "flow_type"]);
        // The number of a field does not depend on the selection.
        assert_eq!(
            selected.proto_lines().collect::<Vec<_>>(),
            ["optional string site = 1001;"]
        );

        assert!(select(&["no_such_field"]).is_err());
        assert!(select(&["bytes", "bytes"]).is_err());
    }

    #[test]
    fn a_field_cannot_reuse_a_name() {
        let text = |name| field(name, Kind::Text, None);
        assert!(Schema::new(&[text("src_addr")], &[]).is_err());
        assert!(Schema::new(&[text("a"), text("a")], &[]).is_err());
        assert!(Schema::new(&[text("site")], &[text("site")]).is_err());
    }

    #[test]
    fn numbers_are_the_given_ones_then_the_next_free() {
        let schema = Schema::new(
            &[
                field("a", Kind::U64, None),
                field("b", Kind::Text, Some(1000)),
            ],
            &[field("c", Kind::F64, None)],
        )
        .unwrap();

        let lines: Vec<_> = schema.proto_lines().collect();
        assert_eq!(
            lines,
            [
                "optional uint64 a = 1001;",
                "optional string b = 1000;",
                "optional double c = 1002;",
            ]
        );
    }

    #[test]
    fn a_number_must_be_free_and_allowed() {
        let numbered = |a, b| {
            Schema::new(
                &[
                    field("a", Kind::Text, Some(a)),
                    field("b", Kind::Text, Some(b)),
                ],
                &[],
            )
        };
        assert!(numbered(1000, 1001).is_ok());
        assert!(numbered(1000, 1000).is_err());
        assert!(numbered(38, 1000).is_err());
        assert!(numbered(19_500, 1000).is_err());
        assert!(numbered(1 << 29, 1000).is_err());
    }

    #[test]
    fn a_value_comes_from_the_flow_the_record_or_the_lookup() {
        let schema = Schema::new(
            &[field("vrf", Kind::U64, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        let mut flow = CommonFlow::new(FlowType::Ipfix, 5, [192, 0, 2, 1].into(), 0);
        flow.src_port = Some(443);
        flow.extra = vec![Some(value::Value::Unsigned32(7))].into();
        let enriched = vec![Some(Value::Text("lab".into()))];

        let value = |name| schema.column(name).unwrap().value(&flow, &enriched);
        assert_eq!(value("flow_type"), Some(Scalar::FlowType(FlowType::Ipfix)));
        assert_eq!(value("time_received_ns"), Some(Scalar::Timestamp(5)));
        assert_eq!(value("src_port"), Some(Scalar::Unsigned(443)));
        assert_eq!(value("dst_port"), None);
        assert_eq!(value("vrf"), Some(Scalar::Unsigned(7)));
        assert_eq!(value("site"), Some(Scalar::String("lab")));
    }
}
