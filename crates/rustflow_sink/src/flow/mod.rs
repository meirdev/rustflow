//! What a flow looks like to the sink: the one field list and the
//! positional enrichment values every encoder consumes.

mod enriched;
pub mod fields;

pub use enriched::Enriched;
pub use fields::{Column, Value, columns, columns_with_values, visit};
