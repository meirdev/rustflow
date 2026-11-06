//! The latest options records, for looking up what an exporter said of
//! something: an interface's name, a selector's sampling, its own
//! statistics.

use std::net::SocketAddr;

use crate::convert::{Record, Scope};
use crate::protocol::information_element::ElementId;
use crate::protocol::value::Value;
use crate::reader::Collector;

/// The latest options record of each kind the exporters sent: one per
/// exporter, observation domain, scope and set of elements, kept by the
/// converters that applied them.
#[derive(Clone, Copy)]
pub struct OptionsTable<'a>(pub(crate) &'a Collector);

impl<'a> OptionsTable<'a> {
    /// The options records of `exporter`'s `domain` whose scope is
    /// `scope`. The exporter is matched as the collector's session key
    /// tells exporters apart: by address alone, unless keyed by port too.
    pub fn get<'s>(
        self,
        exporter: SocketAddr,
        domain: u32,
        scope: &'s [(Scope, Value)],
    ) -> impl Iterator<Item = &'a Record> + use<'a, 's> {
        let exporter = self.0.session_key().of(exporter);
        self.iter()
            .filter(move |&(from, of, record)| {
                from == exporter && of == domain && record.scope == scope
            })
            .map(|(_, _, record)| record)
    }

    /// Every options record that carries `element`, with the exporter it
    /// came from.
    pub fn by_element(self, element: ElementId) -> impl Iterator<Item = (SocketAddr, &'a Record)> {
        self.iter()
            .filter(move |(_, _, record)| record.elements.contains(&element))
            .map(|(exporter, _, record)| (exporter, record))
    }

    /// Every options record, with its exporter and observation domain.
    pub fn iter(self) -> impl Iterator<Item = (SocketAddr, u32, &'a Record)> {
        self.0.options()
    }
}
