use super::CommonFlow;
use crate::information_element::ElementId;
use crate::set::Set;
use crate::value::Value;

/// The information elements to copy from each data record into
/// [`CommonFlow::extra`], in this order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraFields(Box<[ElementId]>);

impl ExtraFields {
    pub fn new(ids: impl IntoIterator<Item = ElementId>) -> Self {
        Self(ids.into_iter().collect())
    }

    pub fn ids(&self) -> &[ElementId] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The values of a flow's [`ExtraFields`], in their order: `None` where
/// the record has no such element.
#[derive(Debug, Clone, Default, PartialEq)]
// One pointer, not a `Vec`: every flow carries it, and moving a larger
// flow slows the collector down even when no extra fields are set.
pub struct ExtraValues(Option<Box<Box<[Option<Value>]>>>);

impl ExtraValues {
    pub fn as_slice(&self) -> &[Option<Value>] {
        self.0.as_deref().map_or(&[], |values| values)
    }

    /// The value of the extra field at `index`, if the record had it.
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.as_slice().get(index)?.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl From<Vec<Option<Value>>> for ExtraValues {
    fn from(values: Vec<Option<Value>>) -> Self {
        Self((!values.is_empty()).then(|| Box::new(values.into_boxed_slice())))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtraValues {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

/// Adds `converted`, the flows of the data records of `sets`, to `flows`,
/// each with the values of `extra` from its record.
pub(crate) fn extend_with_extra<S>(
    flows: &mut impl Extend<CommonFlow>,
    converted: impl Iterator<Item = CommonFlow>,
    sets: &[Set<S>],
    extra: &ExtraFields,
) {
    if extra.is_empty() {
        flows.extend(converted);
        return;
    }
    // The conversions give one flow for each data record, in order.
    let values = extra_values(sets, extra);
    flows.extend(converted.zip(values).map(|(mut flow, values)| {
        flow.extra = values.into();
        flow
    }));
}

fn extra_values<'a, S>(
    sets: &'a [Set<S>],
    extra: &'a ExtraFields,
) -> impl Iterator<Item = Vec<Option<Value>>> + 'a {
    sets.iter().filter_map(Set::as_data).flat_map(|data_set| {
        // An element the template repeats gives its first value.
        let fields = &data_set.template.fields;
        let positions: Vec<_> = extra
            .ids()
            .iter()
            .map(|&id| fields.iter().position(|field| field.element_id() == id))
            .collect();
        data_set.records.iter().map(move |record| {
            positions
                .iter()
                .map(|position| position.and_then(|index| record.get(index).cloned()))
                .collect()
        })
    })
}
