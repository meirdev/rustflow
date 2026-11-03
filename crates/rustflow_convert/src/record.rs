use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use rustflow_protocol::RecordRef;
use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::value::Value;

use crate::time::unix_millis;

/// The protocol a record arrived in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

/// A flow record in IPFIX's information model (RFC 6183 section 8),
/// whatever protocol it arrived in. Each value is of its element's IANA
/// data type.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub protocol: Protocol,
    /// The sequence number of the packet the record arrived in.
    pub sequence_number: u32,
    /// What each value is. Records of one shape, such as those of one
    /// packet, share it.
    pub elements: Arc<[ElementId]>,
    pub values: Vec<Value>,
}

impl Record {
    /// The first value of `element`.
    pub fn first(&self, element: ElementId) -> Option<&Value> {
        self.record_ref().first(element)
    }

    /// Every value of `element`.
    pub fn all(&self, element: ElementId) -> impl Iterator<Item = &Value> {
        self.record_ref().all(element)
    }

    /// Each value with its element, in record order.
    pub fn iter(&self) -> impl Iterator<Item = (ElementId, &Value)> {
        self.elements.iter().copied().zip(&self.values)
    }

    fn record_ref(&self) -> RecordRef<'_, [ElementId]> {
        RecordRef::new(&self.elements, &self.values)
    }
}

/// What the Collecting Process knows of a datagram besides its content
/// (RFC 6183 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The address the datagram came from: its exporter.
    pub exporter: IpAddr,
    /// When the datagram was received, if known.
    pub time: Option<SystemTime>,
}

/// The elements conversion adds to every record of a packet, and their
/// values, kept apart until each record's own are known.
#[derive(Clone)]
pub(crate) struct Additions {
    pub(crate) elements: Vec<ElementId>,
    pub(crate) values: Vec<Value>,
}

impl Additions {
    /// The exporter, its observation domain if the protocol has one, and
    /// when the packet was received (RFC 6183 section 7).
    pub(crate) fn new(received: &Received, observation_domain_id: Option<u32>) -> Self {
        let mut additions = Self {
            elements: Vec::new(),
            values: Vec::new(),
        };
        match received.exporter {
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

    pub(crate) fn push(&mut self, element: ElementId, value: Value) {
        self.elements.push(element);
        self.values.push(value);
    }
}
