//! The Exporting Process (RFC 7011 section 2), the reverse of [`convert`]:
//! records of IPFIX information elements written out as the packets of a
//! protocol, for a collector to read. What a record's elements and values
//! are decides the templates an exporter sends; the exporter keeps the
//! sequence numbers and resends templates as the protocol asks.
//!
//! Each exporter takes records and gives back a packet of its protocol,
//! which the protocol's `write` turns into a datagram. Times in a record
//! are absolute; an exporter whose protocol counts from boot takes when it
//! booted and makes them relative.
//!
//! [`convert`]: crate::convert

use std::time::{SystemTime, UNIX_EPOCH};
use std::{error, fmt};

use crate::protocol::information_element::ElementId;
use crate::protocol::netflow_v9::ScopeType;

pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
pub mod sflow_v5;
mod templated;

/// Why a record cannot be exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportError {
    /// An options record scoped by a NetFlow v9 scope type that no element
    /// carries (RFC 3954 section 6.1), in a protocol whose scopes are
    /// elements.
    Scope(ScopeType),
    /// An options record scoped by an element that is not a NetFlow v9
    /// scope type.
    ScopeElement(ElementId),
    /// An element the protocol has no field for: an enterprise element or
    /// a list in NetFlow v9.
    NoField(ElementId),
    /// A record without an element the protocol's fixed format needs.
    Missing(ElementId),
    /// Records of more shapes than there are template IDs.
    TemplateIds,
    /// A list of records of a template the collector did not have, kept as
    /// sent, which cannot be given a template here.
    UndecodedList(u16),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope(scope) => write!(f, "scope type {scope:?} has no element"),
            Self::ScopeElement(element) => write!(f, "{element} is not a scope type"),
            Self::NoField(element) => write!(f, "{element} has no field in the protocol"),
            Self::Missing(element) => write!(f, "record has no {element}"),
            Self::TemplateIds => write!(f, "no template ID left"),
            Self::UndecodedList(template_id) => {
                write!(f, "list records of template {template_id} were not decoded")
            }
        }
    }
}

impl error::Error for ExportError {}

/// Seconds since 1970 of `time`, modulo 2^32 as headers carry them; zero
/// before 1970.
fn unix_seconds(time: SystemTime) -> u32 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as u32)
}

/// Milliseconds since 1970 of `time`; zero before 1970.
fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

/// The uptime at `time_ms` of an exporter booted at `boot_ms`, modulo 2^32
/// as uptimes wrap. Before boot it wraps too, which a collector reads as
/// the past (RFC 3954 section 5.1).
fn uptime(time_ms: u64, boot_ms: u64) -> u32 {
    time_ms.wrapping_sub(boot_ms) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::information_element::iana;

    #[test]
    fn errors_display_their_cause() {
        assert_eq!(
            ExportError::Scope(ScopeType::LineCard).to_string(),
            "scope type LineCard has no element"
        );
        assert_eq!(
            ExportError::ScopeElement(iana::OCTET_DELTA_COUNT).to_string(),
            "(1) is not a scope type"
        );
        assert_eq!(
            ExportError::NoField(ElementId::from((9, 1))).to_string(),
            "(9/1) has no field in the protocol"
        );
        assert_eq!(
            ExportError::Missing(iana::SOURCE_IPV4_ADDRESS).to_string(),
            "record has no (8)"
        );
        assert_eq!(ExportError::TemplateIds.to_string(), "no template ID left");
        assert_eq!(
            ExportError::UndecodedList(500).to_string(),
            "list records of template 500 were not decoded"
        );
    }

    #[test]
    fn uptimes_wrap_before_boot() {
        assert_eq!(uptime(5_000, 2_000), 3_000);
        assert_eq!(uptime(1_000, 2_000), u32::MAX - 999);
    }
}
