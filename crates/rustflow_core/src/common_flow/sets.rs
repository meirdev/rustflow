use std::time::Instant;

use super::options::ExporterOptions;
use crate::information_element::ElementId;
use crate::netflow_v9::{ScopeField, ScopeType};
use crate::set::Set;
use crate::template::FieldSpecifier;
use crate::value::Value;

pub(super) trait Scope {
    fn element_id(&self) -> Option<ElementId>;

    fn is_partial(&self) -> bool;
}

impl Scope for FieldSpecifier {
    fn element_id(&self) -> Option<ElementId> {
        Some(FieldSpecifier::element_id(self))
    }

    fn is_partial(&self) -> bool {
        matches!(
            FieldSpecifier::element_id(self),
            ElementId::INGRESS_INTERFACE | ElementId::EGRESS_INTERFACE | ElementId::LINE_CARD_ID
        )
    }
}

impl Scope for ScopeField {
    fn element_id(&self) -> Option<ElementId> {
        None
    }

    fn is_partial(&self) -> bool {
        matches!(self.field_type, ScopeType::Interface | ScopeType::LineCard)
    }
}

pub(super) fn data_records<S>(
    sets: &[Set<S>],
) -> impl Iterator<Item = (&[FieldSpecifier], &[Value])> {
    sets.iter().filter_map(Set::as_data).flat_map(|data_set| {
        let fields = data_set.template.fields.as_slice();
        data_set
            .records
            .iter()
            .map(move |record| (fields, record.as_slice()))
    })
}

pub(super) fn learn_options<S: Scope>(
    sets: &[Set<S>],
    domain: u32,
    options: &mut ExporterOptions,
    now: Instant,
) {
    for data_set in sets.iter().filter_map(Set::as_options_data) {
        let template = &data_set.template;
        let partial = template.scope_fields.iter().any(Scope::is_partial);
        let scope = template.scope_fields.iter().map(Scope::element_id);
        let option = template
            .option_fields
            .iter()
            .map(|field| Some(field.element_id()));
        let ids = scope.chain(option);
        for record in &data_set.records {
            let fields = ids
                .clone()
                .zip(record)
                .filter_map(|(id, value)| Some((id?, value)));
            options.learn(domain, partial, fields, now);
        }
    }
}
