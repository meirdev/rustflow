//! The columns of the output, in order: the flow's fields, then the fields
//! added to it. Every encoder writes the columns of one [`Schema`]. The
//! flow's fields come first and in their order, whichever of them are
//! selected, so the encoders write them as one block that skips the
//! others: a call for each field made the CSV encoder a third slower.

use std::collections::HashSet;

use anyhow::{Result, bail};
use rustflow_core::common_flow::CommonFlow;

use crate::enrich::Enriched;
use crate::field::{Field, Kind, Scalar};

/// The protobuf field numbers below this are the flow's own fields, now
/// or later.
const FIRST_ADDED_NUMBER: u32 = 1000;
const MAX_NUMBER: u32 = (1 << 29) - 1;
/// Protobuf keeps these for its implementation.
const RESERVED_NUMBERS: std::ops::RangeInclusive<u32> = 19_000..=19_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// A field of `CommonFlow`, by its position in
    /// `CommonFlow::FIELD_NAMES`.
    Flow(usize),
    Added(Added),
}

/// A field added to the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Added {
    source: Source,
    pub kind: Kind,
    /// Its protobuf field number.
    pub number: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A value of `CommonFlow::extra`, by its position.
    Record(usize),
    /// A value the enrichment looked up, by its position in the row.
    Lookup(usize),
}

impl Added {
    /// The field's value for `flow`, if it has one.
    pub fn value<'a>(&self, flow: &'a CommonFlow, enriched: &'a Enriched) -> Option<Scalar<'a>> {
        match self.source {
            Source::Record(index) => Scalar::of_record(flow.extra.get(index)?, self.kind),
            Source::Lookup(index) => enriched[index].as_ref().map(Scalar::of_table),
        }
    }
}

/// Whether each of the flow's fields is a column, in the order of
/// `CommonFlow::FIELD_NAMES`.
pub type FlowFields = [bool; CommonFlow::FIELD_NAMES.len()];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    columns: Vec<(String, Column)>,
}

impl Schema {
    /// The flow's fields, then `extra`, the fields of `CommonFlow::extra`,
    /// then `enriched`, the fields of the enrichment's row. A name or a
    /// protobuf number may not be used twice; a field without a number is
    /// given the next free one.
    pub fn new(extra: &[Field], enriched: &[Field]) -> Result<Self> {
        let mut columns: Vec<(String, Column)> = CommonFlow::FIELD_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| (name.to_string(), Column::Flow(index)))
            .collect();

        let record = extra
            .iter()
            .enumerate()
            .map(|(i, f)| (Source::Record(i), f));
        let lookup = (enriched.iter().enumerate()).map(|(i, f)| (Source::Lookup(i), f));
        let added: Vec<_> = record.chain(lookup).collect();

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
            if columns.iter().any(|(name, _)| *name == field.name) {
                bail!("Field '{}' is already the name of a column", field.name);
            }
            let number = match field.number {
                Some(number) => number,
                None => free
                    .find(|number| !taken.contains(number))
                    .expect("there are more numbers than fields"),
            };
            let added = Added {
                source,
                kind: field.kind,
                number,
            };
            columns.push((field.name.clone(), Column::Added(added)));
        }
        Ok(Self { columns })
    }

    /// The schema with only the columns `names` list, still in the
    /// schema's order.
    pub fn select(mut self, names: &[String]) -> Result<Self> {
        let mut seen = HashSet::new();
        for name in names {
            if !self.columns.iter().any(|(column, _)| column == name) {
                bail!("Unknown field '{name}'");
            }
            if !seen.insert(name) {
                bail!("Field '{name}' is selected twice");
            }
        }
        self.columns.retain(|(name, _)| seen.contains(name));
        Ok(self)
    }

    /// The flow's fields that are columns.
    pub fn flow_fields(&self) -> FlowFields {
        let mut fields = [false; CommonFlow::FIELD_NAMES.len()];
        for (_, column) in self.columns() {
            if let Column::Flow(index) = column {
                fields[index] = true;
            }
        }
        fields
    }

    pub fn columns(&self) -> impl Iterator<Item = (&str, Column)> {
        self.columns
            .iter()
            .map(|(name, column)| (name.as_str(), *column))
    }

    /// The added fields, after the flow's.
    pub fn added(&self) -> impl Iterator<Item = (&str, Added)> {
        self.columns().filter_map(|(name, column)| match column {
            Column::Flow(_) => None,
            Column::Added(added) => Some((name, added)),
        })
    }

    /// The lines that declare the added fields in `rustflow.proto`.
    pub fn proto_lines(&self) -> impl Iterator<Item = String> {
        self.added().map(|(name, added)| {
            let proto_type = added.kind.proto_type();
            format!("optional {proto_type} {name} = {};", added.number)
        })
    }
}

#[cfg(test)]
mod tests {
    use rustflow_core::common_flow::FlowType;
    use rustflow_core::value::Value;

    use super::*;
    use crate::field;

    fn field(name: &str, kind: Kind, number: Option<u32>) -> Field {
        Field {
            name: name.into(),
            kind,
            number,
        }
    }

    #[test]
    fn columns_are_the_flow_then_the_added_fields() {
        let schema = Schema::new(
            &[field("vrf", Kind::Unsigned, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();

        let columns: Vec<_> = schema.columns().collect();
        let flow_fields = CommonFlow::FIELD_NAMES.len();
        assert_eq!(columns.len(), flow_fields + 2);
        assert_eq!(columns[0], ("flow_type", Column::Flow(0)));
        let added: Vec<_> = schema.added().map(|(name, _)| name).collect();
        assert_eq!(added, ["vrf", "site"]);
    }

    #[test]
    fn a_selection_keeps_the_listed_columns_in_the_schema_order() {
        let schema = Schema::new(
            &[field("vrf", Kind::Unsigned, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        assert_eq!(schema.flow_fields(), [true; CommonFlow::FIELD_NAMES.len()]);
        let select = |names: &[&str]| {
            let names: Vec<_> = names.iter().map(|name| name.to_string()).collect();
            schema.clone().select(&names)
        };

        let selected = select(&["site", "bytes", "flow_type"]).unwrap();
        let names: Vec<_> = selected.columns().map(|(name, _)| name).collect();
        assert_eq!(names, ["flow_type", "bytes", "site"]);
        let flags = selected.flow_fields();
        let bytes = CommonFlow::FIELD_NAMES
            .iter()
            .position(|name| *name == "bytes");
        assert_eq!(flags.iter().filter(|selected| **selected).count(), 2);
        assert!(flags[0] && flags[bytes.unwrap()]);
        // The number of an added field does not depend on the selection.
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
                field("a", Kind::Unsigned, None),
                field("b", Kind::Text, Some(1000)),
            ],
            &[field("c", Kind::Float, None)],
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
    fn a_value_comes_from_the_record_or_from_the_lookup() {
        let schema = Schema::new(
            &[field("vrf", Kind::Unsigned, None)],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        let mut flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 0);
        flow.extra = vec![Some(Value::Unsigned32(7))].into();
        let enriched = vec![Some(field::Value::Text("lab".into()))];

        let values: Vec<_> = schema
            .added()
            .map(|(_, added)| added.value(&flow, &enriched))
            .collect();
        assert_eq!(
            values,
            [Some(Scalar::Unsigned(7)), Some(Scalar::String("lab"))]
        );
    }
}
