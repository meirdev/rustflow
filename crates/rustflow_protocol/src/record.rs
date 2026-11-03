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

/// A template that is no more than its elements, all of them known.
impl Elements for [ElementId] {
    fn elements(&self) -> impl Iterator<Item = Option<ElementId>> {
        self.iter().map(|&element| Some(element))
    }
}

/// A record's values, with the template that says what they are.
#[derive(Debug)]
pub struct RecordRef<'a, T: ?Sized> {
    pub template: &'a T,
    pub values: &'a [Value],
}

impl<T: ?Sized> Clone for RecordRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for RecordRef<'_, T> {}

impl<'a, T: ?Sized> RecordRef<'a, T> {
    pub fn new(template: &'a T, values: &'a [Value]) -> Self {
        Self { template, values }
    }
}

impl<'a, T: Elements + ?Sized> RecordRef<'a, T> {
    /// Each value with its element, in record order.
    pub fn iter(self) -> impl Iterator<Item = (Option<ElementId>, &'a Value)> {
        self.template.elements().zip(self.values)
    }

    /// The first value of `element`, by a scan of the template's fields.
    pub fn first(self, element: ElementId) -> Option<&'a Value> {
        self.all(element).next()
    }

    /// Every value of `element`, which a template may hold more than once.
    pub fn all(self, element: ElementId) -> impl Iterator<Item = &'a Value> {
        self.iter()
            .filter(move |(id, _)| *id == Some(element))
            .map(|(_, value)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::information_element::iana;

    #[test]
    fn a_list_of_elements_is_a_template() {
        let elements = [
            iana::SOURCE_TRANSPORT_PORT,
            iana::DESTINATION_TRANSPORT_PORT,
        ];
        let values = [Value::Unsigned16(443), Value::Unsigned16(51001)];
        let record = RecordRef::new(&elements[..], &values);

        assert_eq!(
            record.first(iana::DESTINATION_TRANSPORT_PORT),
            Some(&Value::Unsigned16(51001))
        );
        assert_eq!(
            record.iter().collect::<Vec<_>>(),
            [
                (Some(iana::SOURCE_TRANSPORT_PORT), &values[0]),
                (Some(iana::DESTINATION_TRANSPORT_PORT), &values[1]),
            ]
        );
    }
}
