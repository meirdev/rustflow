use std::time::Instant;

use super::options::{ExporterOptions, Extent};
use crate::information_element::ElementId;
use crate::netflow_v9::{ScopeField, ScopeType};
use crate::set::Set;
use crate::template::FieldSpecifier;
use crate::value::Value;

pub(super) trait Scope {
    fn element_id(&self) -> Option<ElementId>;

    fn is_partial(&self) -> bool;

    fn is_system(&self) -> bool;
}

impl Scope for FieldSpecifier {
    fn element_id(&self) -> Option<ElementId> {
        Some(FieldSpecifier::element_id(self))
    }

    fn is_partial(&self) -> bool {
        matches!(
            FieldSpecifier::element_id(self),
            ElementId::INGRESS_INTERFACE
                | ElementId::EGRESS_INTERFACE
                | ElementId::LINE_CARD_ID
                | ElementId::TEMPLATE_ID
        )
    }

    fn is_system(&self) -> bool {
        false
    }
}

impl Scope for ScopeField {
    fn element_id(&self) -> Option<ElementId> {
        None
    }

    fn is_partial(&self) -> bool {
        // A scope this crate does not know may be any part of the domain.
        matches!(
            self.field_type,
            ScopeType::Interface
                | ScopeType::LineCard
                | ScopeType::Template
                | ScopeType::Unassigned(_)
        )
    }

    fn is_system(&self) -> bool {
        self.field_type == ScopeType::System
    }
}

fn extent<S: Scope>(scopes: &[S]) -> Extent {
    if scopes.iter().any(Scope::is_partial) {
        Extent::Partial
    } else if scopes.iter().any(Scope::is_system) {
        Extent::System
    } else {
        Extent::Domain
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
        let extent = extent(&template.scope_fields);
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
            options.learn(domain, extent, fields, now);
        }
    }
}
