use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;

use crate::convert::time::unix_millis;
use crate::protocol::Protocol;
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::netflow_v9::ScopeType;
use crate::protocol::value::Value;

/// A record in IPFIX's information model (RFC 6183 section 8), whatever
/// protocol it arrived in: a flow, or with a scope, options describing
/// what the scope names. Each value is of its element's IANA data type.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub protocol: Protocol,
    /// The sequence number of the packet the record arrived in.
    pub sequence_number: u32,
    /// What an options record describes (RFC 7011 section 3.4.2.1); empty
    /// for a flow.
    pub scope: Vec<(Scope, Value)>,
    /// What each value is. Records of one shape, such as those of one
    /// packet, share it.
    pub elements: Arc<Elements>,
    pub values: Vec<Value>,
}

/// The elements of records of one shape, and where each is, so that a
/// value is found by its element without a scan of the record. Built once
/// per shape; records of the shape share it.
#[derive(Debug, PartialEq, Eq)]
pub struct Elements {
    list: Box<[ElementId]>,
    /// The first position of each IANA element, by id, as far as the
    /// largest id the list has; [`NONE`] for an id the list lacks.
    iana: Box<[usize]>,
    /// The first position of each enterprise element, sorted by element.
    enterprise: Box<[(ElementId, usize)]>,
}

const NONE: usize = usize::MAX;

impl Elements {
    /// Where `element` first is in a record of these elements.
    pub fn position(&self, element: ElementId) -> Option<usize> {
        match element.enterprise_number {
            None => self
                .iana
                .get(usize::from(element.id))
                .copied()
                .filter(|&position| position != NONE),
            Some(_) => {
                let found = self
                    .enterprise
                    .binary_search_by_key(&element, |&(known, _)| known)
                    .ok()?;
                Some(self.enterprise[found].1)
            }
        }
    }
}

impl From<Vec<ElementId>> for Elements {
    fn from(list: Vec<ElementId>) -> Self {
        let ids = list
            .iter()
            .filter(|element| element.enterprise_number.is_none())
            .map(|element| usize::from(element.id) + 1)
            .max()
            .unwrap_or(0);
        let mut iana = vec![NONE; ids];
        let mut enterprise = Vec::new();
        for (position, &element) in list.iter().enumerate() {
            match element.enterprise_number {
                None => {
                    let slot = &mut iana[usize::from(element.id)];
                    if *slot == NONE {
                        *slot = position;
                    }
                }
                Some(_) => enterprise.push((element, position)),
            }
        }
        enterprise.sort();
        enterprise.dedup_by_key(|&mut (element, _)| element);
        Self {
            list: list.into(),
            iana: iana.into(),
            enterprise: enterprise.into(),
        }
    }
}

impl FromIterator<ElementId> for Elements {
    fn from_iter<I: IntoIterator<Item = ElementId>>(iter: I) -> Self {
        Vec::from_iter(iter).into()
    }
}

impl Deref for Elements {
    type Target = [ElementId];

    fn deref(&self) -> &[ElementId] {
        &self.list
    }
}

/// What a scope value names: an element's value, as IPFIX scopes and the
/// NetFlow v9 scope types it has elements for are; or else, for a v9 scope
/// type unassigned when RFC 3954 was written, that type's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Element(ElementId),
    Type(ScopeType),
}

impl Record {
    pub fn is_options(&self) -> bool {
        !self.scope.is_empty()
    }

    /// The first value of `element`.
    pub fn first(&self, element: ElementId) -> Option<&Value> {
        self.values.get(self.elements.position(element)?)
    }

    /// Every value of `element`, which a record may hold more than once.
    pub fn all(&self, element: ElementId) -> impl Iterator<Item = &Value> {
        self.iter()
            .filter(move |(known, _)| *known == element)
            .map(|(_, value)| value)
    }

    /// Each value with its element, in record order.
    pub fn iter(&self) -> impl Iterator<Item = (ElementId, &Value)> {
        self.elements.iter().copied().zip(&self.values)
    }

    /// The scope values that are of an element, as IPFIX scopes are.
    pub fn scope_elements(&self) -> impl Iterator<Item = (ElementId, &Value)> {
        self.scope.iter().filter_map(|(scope, value)| match scope {
            Scope::Element(element) => Some((*element, value)),
            Scope::Type(_) => None,
        })
    }
}

/// What the Collecting Process knows of a datagram besides its content
/// (RFC 6183 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The transport address the datagram came from: its exporter's, which
    /// with the collector's own identifies the transport session (RFC 7011
    /// section 3.1). Templates and sessions are scoped by it, so two
    /// exporting processes on one host are told apart.
    pub exporter: SocketAddr,
    /// When the datagram was received, if known.
    pub time: Option<SystemTime>,
}

/// A record's fields as conversion gathers them, elements and values side
/// by side.
#[derive(Debug, Clone, Default)]
pub(crate) struct Fields {
    pub(crate) elements: Vec<ElementId>,
    pub(crate) values: Vec<Value>,
    /// Which of the low IANA elements there is a field of, so that
    /// [`has`](Self::has) needs no scan for them.
    seen: Seen,
}

/// A bit per IANA element ID below [`SEEN_IDS`].
#[derive(Debug, Clone, Copy, Default)]
struct Seen([u64; SEEN_IDS / 64]);

const SEEN_IDS: usize = 512;

impl Seen {
    fn slot(element: ElementId) -> Option<(usize, u64)> {
        if element.enterprise_number.is_some() || usize::from(element.id) >= SEEN_IDS {
            return None;
        }
        Some((usize::from(element.id) / 64, 1 << (element.id % 64)))
    }

    fn insert(&mut self, element: ElementId) {
        if let Some((word, bit)) = Self::slot(element) {
            self.0[word] |= bit;
        }
    }

    /// Whether `element` was inserted; `None` for an element not tracked.
    fn contains(&self, element: ElementId) -> Option<bool> {
        Self::slot(element).map(|(word, bit)| self.0[word] & bit != 0)
    }
}

impl Fields {
    /// Every element [`additions`](Self::additions) may add.
    pub(crate) const ADDED: [ElementId; 5] = [
        iana::ORIGINAL_EXPORTER_IPV4_ADDRESS,
        iana::ORIGINAL_EXPORTER_IPV6_ADDRESS,
        iana::EXPORTER_TRANSPORT_PORT,
        iana::ORIGINAL_OBSERVATION_DOMAIN_ID,
        iana::COLLECTION_TIME_MILLISECONDS,
    ];

    /// The fields conversion adds to every record of a packet: the
    /// exporter and its port, its observation domain if the protocol has
    /// one, and when the packet was received (RFC 6183 section 7). The
    /// port has no "original" element, so `exporterTransportPort` carries
    /// it.
    pub(crate) fn additions(received: &Received, observation_domain_id: Option<u32>) -> Self {
        let mut additions = Self::default();
        match received.exporter.ip() {
            IpAddr::V4(address) => {
                additions.push(
                    iana::ORIGINAL_EXPORTER_IPV4_ADDRESS,
                    Value::Ipv4Address(address),
                );
            }
            IpAddr::V6(address) => {
                additions.push(
                    iana::ORIGINAL_EXPORTER_IPV6_ADDRESS,
                    Value::Ipv6Address(address),
                );
            }
        }
        additions.push(
            iana::EXPORTER_TRANSPORT_PORT,
            Value::Unsigned16(received.exporter.port()),
        );
        if let Some(domain) = observation_domain_id {
            additions.push(
                iana::ORIGINAL_OBSERVATION_DOMAIN_ID,
                Value::Unsigned32(domain),
            );
        }
        if let Some(millis) = received.time.and_then(unix_millis) {
            additions.push(
                iana::COLLECTION_TIME_MILLISECONDS,
                Value::DateTimeMilliseconds(millis),
            );
        }
        additions
    }

    /// The additions a record of `elements` lacks. A record from an
    /// upstream Mediator names its Original Exporter, observation domain and
    /// collection time already; those are kept, not joined by what this
    /// collector saw of the Mediator (RFC 7119 sections 5 and 6).
    pub(crate) fn lacking(&self, elements: &[ElementId]) -> Cow<'_, Self> {
        let has = |element| elements.contains(&element);
        let names_exporter =
            has(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS) || has(iana::ORIGINAL_EXPORTER_IPV6_ADDRESS);
        let lacks = |element| match element {
            iana::ORIGINAL_EXPORTER_IPV4_ADDRESS
            | iana::ORIGINAL_EXPORTER_IPV6_ADDRESS
            | iana::EXPORTER_TRANSPORT_PORT => !names_exporter && !has(element),
            element => !has(element),
        };
        if self.elements.iter().all(|&element| lacks(element)) {
            return Cow::Borrowed(self);
        }
        let (elements, values) = self
            .elements
            .iter()
            .zip(&self.values)
            .filter(|&(&element, _)| lacks(element))
            .map(|(&element, value)| (element, value.clone()))
            .unzip();
        Cow::Owned(Self::new(elements, values))
    }

    pub(crate) fn new(elements: Vec<ElementId>, values: Vec<Value>) -> Self {
        let mut seen = Seen::default();
        for &element in &elements {
            seen.insert(element);
        }
        Self {
            elements,
            values,
            seen,
        }
    }

    pub(crate) fn push(&mut self, element: ElementId, value: Value) {
        self.elements.push(element);
        self.values.push(value);
        self.seen.insert(element);
    }

    /// Adds a field unless there is one of that element already: of two
    /// sources that describe a packet alike, the first one wins.
    pub(crate) fn add(&mut self, element: ElementId, value: Value) {
        if !self.has(element) {
            self.push(element, value);
        }
    }

    pub(crate) fn has(&self, element: ElementId) -> bool {
        self.seen
            .contains(element)
            .unwrap_or_else(|| self.elements.contains(&element))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (ElementId, &Value)> {
        self.elements.iter().copied().zip(&self.values)
    }

    pub(crate) fn append(&mut self, mut other: Self) {
        for (word, bits) in self.seen.0.iter_mut().zip(other.seen.0) {
            *word |= bits;
        }
        self.elements.append(&mut other.elements);
        self.values.append(&mut other.values);
    }

    /// The record of these fields, its elements shared with the records of
    /// `shapes` that have the same.
    pub(crate) fn into_record(
        self,
        protocol: Protocol,
        sequence_number: u32,
        shapes: &mut Shapes,
    ) -> Record {
        Record {
            protocol,
            sequence_number,
            scope: Vec::new(),
            elements: shapes.get(self.elements),
            values: self.values,
        }
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self::new(Vec::with_capacity(capacity), Vec::with_capacity(capacity))
    }
}

/// The element lists of the records converted lately, so that records of
/// one shape share theirs, even when shapes alternate as sFlow samples'
/// do.
#[derive(Debug, Default)]
pub(crate) struct Shapes(Vec<Arc<Elements>>);

/// Shapes kept; the oldest goes when another comes.
const SHAPES_KEPT: usize = 32;

impl Shapes {
    pub(crate) fn get(&mut self, elements: Vec<ElementId>) -> Arc<Elements> {
        if let Some(known) = self.0.iter().find(|known| known[..] == elements[..]) {
            return Arc::clone(known);
        }
        if self.0.len() >= SHAPES_KEPT {
            self.0.remove(0);
        }
        let shape = Arc::new(Elements::from(elements));
        self.0.push(Arc::clone(&shape));
        shape
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_elements_position_is_its_first() {
        let vendor = ElementId::from((9, 1));
        let elements = Elements::from(vec![
            iana::OCTET_DELTA_COUNT,
            vendor,
            iana::PACKET_DELTA_COUNT,
            iana::OCTET_DELTA_COUNT,
            vendor,
        ]);
        assert_eq!(elements.position(iana::OCTET_DELTA_COUNT), Some(0));
        assert_eq!(elements.position(vendor), Some(1));
        assert_eq!(elements.position(iana::PACKET_DELTA_COUNT), Some(2));
        assert_eq!(elements.position(iana::PROTOCOL_IDENTIFIER), None);
        assert_eq!(elements.position(iana::COLLECTION_TIME_MILLISECONDS), None);
        assert_eq!(elements.position(ElementId::from((9, 2))), None);
        assert_eq!(elements.len(), 5);
    }
}
