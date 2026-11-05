//! The latest options records, for looking up what an exporter said of
//! something: an interface's name, a selector's sampling, its own
//! statistics.

use std::collections::HashMap;
use std::net::IpAddr;

use rustflow_convert::{Record, Scope};
use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::value::Value;

/// Observation domains the table may keep records for, and records one
/// domain may have; the exporters decide how many they send.
const MAX_DOMAINS: usize = 4096;
const MAX_RECORDS_PER_DOMAIN: usize = 1024;

/// The latest options record of each kind an exporter sent: one per
/// observation domain, scope and set of elements.
#[derive(Debug, Default)]
pub struct OptionsTable {
    domains: HashMap<(IpAddr, u32), Vec<Record>>,
}

impl OptionsTable {
    /// Keeps `record`, an options record from `exporter`, in place of the
    /// one it supersedes: that of the same scope and elements.
    pub fn insert(&mut self, exporter: IpAddr, record: Record) {
        let domain = record
            .first(iana::ORIGINAL_OBSERVATION_DOMAIN_ID)
            .and_then(Value::as_u64)
            .and_then(|domain| u32::try_from(domain).ok())
            .unwrap_or(0);
        let key = (exporter, domain);
        if !self.domains.contains_key(&key) && self.domains.len() >= MAX_DOMAINS {
            return;
        }
        let records = self.domains.entry(key).or_default();
        let same_kind = records
            .iter()
            .position(|known| known.scope == record.scope && known.elements == record.elements);
        match same_kind {
            Some(index) => records[index] = record,
            None if records.len() < MAX_RECORDS_PER_DOMAIN => records.push(record),
            None => {}
        }
    }

    /// The options records of `exporter`'s `domain` whose scope is
    /// `scope`.
    pub fn get<'a>(
        &'a self,
        exporter: IpAddr,
        domain: u32,
        scope: &'a [(Scope, Value)],
    ) -> impl Iterator<Item = &'a Record> {
        self.domains
            .get(&(exporter, domain))
            .into_iter()
            .flatten()
            .filter(move |record| record.scope == scope)
    }

    /// Every options record that carries `element`, with the exporter it
    /// came from.
    pub fn by_element(&self, element: ElementId) -> impl Iterator<Item = (IpAddr, &Record)> {
        self.iter()
            .filter(move |(_, record)| record.elements.contains(&element))
    }

    pub fn iter(&self) -> impl Iterator<Item = (IpAddr, &Record)> {
        self.domains.iter().flat_map(|(&(exporter, _), records)| {
            records.iter().map(move |record| (exporter, record))
        })
    }

    pub fn len(&self) -> usize {
        self.domains.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
