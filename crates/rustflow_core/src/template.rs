use std::sync::Arc;

use crate::information_element::{DataType, ElementId};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Template {
    pub template_id: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OptionsTemplate<S = FieldSpecifier> {
    pub template_id: u16,
    pub scope_fields: Vec<S>,
    pub option_fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FieldSpecifier {
    /// The information element's ID, without the enterprise bit.
    pub information_element_id: u16,
    /// In octets. In IPFIX, 65535 marks a variable-length field.
    pub field_length: u16,
    /// The private enterprise number of a vendor's element; `None` for an
    /// IANA element.
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    pub fn element_id(&self) -> ElementId {
        ElementId::new_unchecked(self.enterprise_number, self.information_element_id)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TemplateRef<S = FieldSpecifier> {
    Data(Arc<Template>),
    Options(Arc<OptionsTemplate<S>>),
}

impl<S> TemplateRef<S> {
    pub fn template_id(&self) -> u16 {
        match self {
            Self::Data(template) => template.template_id,
            Self::Options(template) => template.template_id,
        }
    }
}

impl TemplateRef {
    pub fn fields(&self) -> impl Iterator<Item = &FieldSpecifier> {
        let (scope_fields, fields): (&[_], &[_]) = match self {
            Self::Data(template) => (&[], &template.fields),
            Self::Options(template) => (&template.scope_fields, &template.option_fields),
        };
        scope_fields.iter().chain(fields)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTemplate<S = FieldSpecifier> {
    pub(crate) template: TemplateRef<S>,
    pub(crate) data_types: Box<[Option<DataType>]>,
}
