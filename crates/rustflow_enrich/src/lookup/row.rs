use std::fmt;
use std::ops::Index;
use std::sync::Arc;

/// Column names shared by every row loaded from one source. Cloning a schema
/// shares the underlying column list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema(Arc<[String]>);

impl Schema {
    pub fn new(columns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(columns.into_iter().map(Into::into).collect())
    }

    pub fn columns(&self) -> &[String] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn index_of(&self, column: &str) -> Option<usize> {
        self.0.iter().position(|c| c == column)
    }

    /// Build a row from positional values, one per schema column. `None`
    /// marks a missing or empty cell.
    ///
    /// # Panics
    ///
    /// Panics if the number of values differs from the number of columns.
    pub fn row(&self, values: impl IntoIterator<Item = Option<String>>) -> Row {
        let values: Box<[_]> = values.into_iter().collect();
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

/// One record's values, stored positionally against a shared [`Schema`].
#[derive(Clone, PartialEq, Eq)]
pub struct Row {
    schema: Schema,
    values: Box<[Option<String>]>,
}

impl Row {
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The value for `column`, or `None` if the column is not in the schema or
    /// the cell was empty. This scans the column names; a hot path should
    /// resolve [`Schema::index_of`] once and read [`Row::values`] by index.
    pub fn get(&self, column: &str) -> Option<&str> {
        self.values.get(self.schema.index_of(column)?)?.as_deref()
    }

    /// Positional values, aligned with `schema().columns()`.
    pub fn values(&self) -> &[Option<String>] {
        &self.values
    }

    /// Present `(column, value)` pairs in schema order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.schema
            .columns()
            .iter()
            .zip(&self.values)
            .filter_map(|(column, value)| Some((column.as_str(), value.as_deref()?)))
    }
}

impl Index<&str> for Row {
    type Output = String;

    /// # Panics
    ///
    /// Panics if `column` has no value. Use [`Row::get`] for a fallible lookup.
    fn index(&self, column: &str) -> &String {
        self.schema
            .index_of(column)
            .and_then(|index| self.values[index].as_ref())
            .unwrap_or_else(|| panic!("no value for column '{column}'"))
    }
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}
