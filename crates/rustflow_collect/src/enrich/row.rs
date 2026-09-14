use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema(Arc<[String]>);

impl Schema {
    pub fn new(columns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(columns.into_iter().map(Into::into).collect())
    }

    pub fn columns(&self) -> &[String] {
        &self.0
    }

    pub fn row(&self, values: impl IntoIterator<Item = Option<String>>) -> Row {
        let values: Box<[_]> = values.into_iter().map(|v| v.map(Arc::from)).collect();
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

/// Values are shared, so cloning a row or copying a value into the
/// enrichment output is a refcount bump.
#[derive(Clone, PartialEq, Eq)]
pub struct Row {
    schema: Schema,
    values: Box<[Option<Arc<str>>]>,
}

impl Row {
    pub fn get(&self, column: &str) -> Option<&str> {
        let index = self.schema.columns().iter().position(|c| c == column)?;
        self.values[index].as_deref()
    }

    pub fn values(&self) -> &[Option<Arc<str>>] {
        &self.values
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.schema
            .columns()
            .iter()
            .zip(&self.values)
            .filter_map(|(column, value)| Some((column.as_str(), value.as_deref()?)))
    }
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}
