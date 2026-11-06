//! What the NetFlow v9 and IPFIX exporters share: a template for each
//! shape of record, and when the templates are sent.

use std::time::{Duration, SystemTime};

use crate::convert::{Record, Scope};
use crate::export::ExportError;
use crate::protocol::information_element::ElementId;
use crate::protocol::ipfix::MIN_TEMPLATE_ID;

/// The templates made so far, one per shape, and whether they are due in
/// the next packet: at first, when one is new, after the refresh interval,
/// and on request.
#[derive(Debug)]
pub(crate) struct Catalog<T> {
    templates: Vec<Shaped<T>>,
    /// The template of the last record exported, where the next record is
    /// looked for first.
    last: usize,
    refresh: Option<Duration>,
    sent: Option<SystemTime>,
    due: bool,
}

/// A template with the shape of the records it is for.
#[derive(Debug)]
struct Shaped<T> {
    scope: Box<[Scope]>,
    elements: Box<[ElementId]>,
    template: T,
}

impl<T> Shaped<T> {
    fn is_for(&self, record: &Record) -> bool {
        self.elements[..] == record.elements[..]
            && self.scope.len() == record.scope.len()
            && self
                .scope
                .iter()
                .zip(&record.scope)
                .all(|(known, (scope, _))| known == scope)
    }
}

impl<T> Catalog<T> {
    pub(crate) fn new() -> Self {
        Self {
            templates: Vec::new(),
            last: 0,
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

    /// The template of `record`'s shape, which `make` makes with its
    /// template ID when the shape is new.
    pub(crate) fn template_of(
        &mut self,
        record: &Record,
        make: impl FnOnce(u16) -> Result<T, ExportError>,
    ) -> Result<&T, ExportError> {
        let known = match self.templates.get(self.last) {
            Some(last) if last.is_for(record) => Some(self.last),
            _ => self
                .templates
                .iter()
                .position(|shaped| shaped.is_for(record)),
        };
        let index = match known {
            Some(index) => index,
            None => {
                let template_id =
                    u16::try_from(usize::from(MIN_TEMPLATE_ID) + self.templates.len())
                        .map_err(|_| ExportError::TemplateIds)?;
                self.templates.push(Shaped {
                    scope: record.scope.iter().map(|(scope, _)| *scope).collect(),
                    elements: record.elements.to_vec().into(),
                    template: make(template_id)?,
                });
                self.due = true;
                self.templates.len() - 1
            }
        };
        self.last = index;
        Ok(&self.templates[index].template)
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
