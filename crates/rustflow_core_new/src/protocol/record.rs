use std::sync::Arc;

use crate::protocol::value::Value;

/// The records of a data set, with the template they were decoded by.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSet<T> {
    pub template: Arc<T>,
    /// Each record's values, in template order: for options data, the scope
    /// values first.
    pub records: Vec<Vec<Value>>,
}
