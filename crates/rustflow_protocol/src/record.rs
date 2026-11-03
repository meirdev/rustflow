//! Data records, and their values looked up by the elements they are of.

use std::sync::Arc;

use crate::information_element::ElementId;
use crate::value::Value;

/// The records of a data set, with the template they were decoded by.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSet<T> {
    pub template: Arc<T>,
    /// Each record's values, in template order: for options data, the scope
    /// values first.
    pub records: Vec<Vec<Value>>,
}

impl<T> DataSet<T> {
    pub fn records(&self) -> impl Iterator<Item = RecordRef<'_, T>> {
        self.records
            .iter()
            .map(|values| RecordRef::new(&*self.template, values))
    }
}

/// What a template says each of its records' values is.
pub trait Elements {
    /// The element of each value, in record order; `None` for a value of no
    /// element, such as a NetFlow v9 scope field.
    fn elements(&self) -> impl Iterator<Item = Option<ElementId>>;
}

/// A record's values, with the template that says what they are.
#[derive(Debug, Clone, Copy)]
pub struct RecordRef<'a, T> {
    pub template: &'a T,
    pub values: &'a [Value],
}

impl<'a, T> RecordRef<'a, T> {
    pub fn new(template: &'a T, values: &'a [Value]) -> Self {
        Self { template, values }
    }
}

impl<'a, T: Elements> RecordRef<'a, T> {
    /// The first value of `element`, by a scan of the template's fields.
    pub fn first(&self, element: ElementId) -> Option<&'a Value> {
        self.all(element).next()
    }

    /// Every value of `element`, which a template may hold more than once.
    pub fn all(&self, element: ElementId) -> impl Iterator<Item = &'a Value> {
        self.template
            .elements()
            .zip(self.values)
            .filter(move |(id, _)| *id == Some(element))
            .map(|(_, value)| value)
    }
}
