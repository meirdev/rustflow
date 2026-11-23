use std::fmt;
use std::sync::Arc;

use crate::field::{Kind, Value};

/// The columns of a source's rows, and the kind of each one's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema(Arc<[(String, Kind)]>);

impl Schema {
    pub fn new(columns: impl IntoIterator<Item = (impl Into<String>, Kind)>) -> Self {
        Self(
            columns
                .into_iter()
                .map(|(name, kind)| (name.into(), kind))
                .collect(),
        )
    }

    pub fn columns(&self) -> &[(String, Kind)] {
        &self.0
    }

    pub fn row(&self, values: impl IntoIterator<Item = Option<Value>>) -> Row {
        let values: Arc<[_]> = values.into_iter().collect();
        assert_eq!(
            values.len(),
            self.0.len(),
            "row has {} values for {} columns",
            values.len(),
            self.0.len()
        );
        Row {
            schema: self.clone(),
            values,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct Row {
    schema: Schema,
    values: Arc<[Option<Value>]>,
}

impl Row {
    pub fn values(&self) -> &[Option<Value>] {
        &self.values
    }
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let columns = self.schema.columns().iter().map(|(name, _)| name);
        let present = columns
            .zip(self.values.iter())
            .filter_map(|(column, value)| Some((column, value.as_ref()?)));
        f.debug_map().entries(present).finish()
    }
}
