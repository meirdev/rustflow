//! What the NetFlow v9 and IPFIX exporters share: a template for each kind
//! of record, and when the templates are sent.

use std::time::{Duration, SystemTime};

use crate::convert::{Record, Scope};
use crate::export::ExportError;
use crate::protocol::information_element::ElementId;
use crate::protocol::ipfix::MIN_TEMPLATE_ID;
use crate::protocol::value::Value;

/// The templates made so far, one per field list, and whether they are due
/// in the next packet: at first, when one is new, after the refresh
/// interval, and on request. A template is its fields, `F` being the
/// protocol's field: records whose values take the same fields share one.
#[derive(Debug)]
pub(crate) struct Catalog<T, F> {
    templates: Vec<Shaped<T, F>>,
    /// The template of the last record exported, where the next record is
    /// looked for first.
    last: usize,
    /// The fields of the record being placed, kept for their room.
    scope_fields: Vec<F>,
    fields: Vec<F>,
    refresh: Option<Duration>,
    sent: Option<SystemTime>,
    due: bool,
}

/// A template with the fields it is of.
#[derive(Debug)]
struct Shaped<T, F> {
    scope_fields: Box<[F]>,
    fields: Box<[F]>,
    template: T,
}

impl<T, F: Copy + PartialEq> Catalog<T, F> {
    pub(crate) fn new() -> Self {
        Self {
            templates: Vec::new(),
            last: 0,
            scope_fields: Vec::new(),
            fields: Vec::new(),
            refresh: None,
            sent: None,
            due: true,
        }
    }

    pub(crate) fn refresh_every(&mut self, every: Duration) {
        self.refresh = Some(every);
    }

    pub(crate) fn resend(&mut self) {
        self.due = true;
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.templates.iter().map(|shaped| &shaped.template)
    }

    /// The template of records like `record`: of the fields `scope_field`
    /// and `field` give its scope values and values, which `make` makes
    /// into a template with its ID when they are new.
    pub(crate) fn template_of(
        &mut self,
        record: &Record,
        scope_field: impl Fn(Scope, &Value) -> Result<F, ExportError>,
        field: impl Fn(ElementId, &Value) -> Result<F, ExportError>,
        make: impl FnOnce(u16, Vec<F>, Vec<F>) -> T,
    ) -> Result<&T, ExportError> {
        let (mut scope_fields, mut fields) = (
            std::mem::take(&mut self.scope_fields),
            std::mem::take(&mut self.fields),
        );
        scope_fields.clear();
        fields.clear();
        for (scope, value) in &record.scope {
            scope_fields.push(scope_field(*scope, value)?);
        }
        for (element, value) in record.iter() {
            fields.push(field(element, value)?);
        }
        let index = self.index_for(&scope_fields, &fields, make);
        self.scope_fields = scope_fields;
        self.fields = fields;
        Ok(&self.templates[index?].template)
    }

    /// The template of `scope_fields` and `fields`, which `make` makes with
    /// its ID when they are new.
    pub(crate) fn template_for(
        &mut self,
        scope_fields: &[F],
        fields: &[F],
        make: impl FnOnce(u16, Vec<F>, Vec<F>) -> T,
    ) -> Result<&T, ExportError> {
        let index = self.index_for(scope_fields, fields, make)?;
        Ok(&self.templates[index].template)
    }

    fn index_for(
        &mut self,
        scope_fields: &[F],
        fields: &[F],
        make: impl FnOnce(u16, Vec<F>, Vec<F>) -> T,
    ) -> Result<usize, ExportError> {
        let is_for = |shaped: &Shaped<T, F>| {
            shaped.scope_fields[..] == *scope_fields && shaped.fields[..] == *fields
        };
        let known = match self.templates.get(self.last) {
            Some(last) if is_for(last) => Some(self.last),
            _ => self.templates.iter().position(is_for),
        };
        let index = match known {
            Some(index) => index,
            None => {
                let template_id =
                    u16::try_from(usize::from(MIN_TEMPLATE_ID) + self.templates.len())
                        .map_err(|_| ExportError::TemplateIds)?;
                self.templates.push(Shaped {
                    scope_fields: scope_fields.into(),
                    fields: fields.into(),
                    template: make(template_id, scope_fields.to_vec(), fields.to_vec()),
                });
                self.due = true;
                self.templates.len() - 1
            }
        };
        self.last = index;
        Ok(index)
    }

    /// Whether the templates go in a packet sent at `now`, which then
    /// counts as having sent them.
    pub(crate) fn take_due(&mut self, now: SystemTime) -> bool {
        let refreshed = match (self.refresh, self.sent) {
            (Some(every), Some(sent)) => now.duration_since(sent).is_ok_and(|since| since >= every),
            _ => false,
        };
        if !(self.due || refreshed) {
            return false;
        }
        self.due = false;
        self.sent = Some(now);
        true
    }
}
