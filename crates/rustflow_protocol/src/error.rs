use std::{error, fmt};

use rustflow_bytes::Truncated;

/// Why a datagram could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated(Truncated),
    /// The header carries a version other than the parser's.
    Version(u32),
    /// A set's length is shorter than its own header.
    SetLength(u16),
    /// A template ID in the range reserved for set IDs.
    TemplateId(u16),
    /// A message's length is shorter than its own header.
    MessageLength(u16),
    /// An options template's scope field count is zero, or more than its
    /// field count.
    ScopeFieldCount(u16),
    /// An sFlow address of a type other than unknown, IPv4 or IPv6.
    AddressType(u32),
    /// An sFlow AS path segment other than a set or a sequence.
    AsPathSegmentType(u32),
    /// A string that is not UTF-8.
    Utf8,
}

impl From<Truncated> for ParseError {
    fn from(e: Truncated) -> Self {
        Self::Truncated(e)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(e) => write!(f, "truncated: {e}"),
            Self::Version(version) => write!(f, "unexpected version {version}"),
            Self::SetLength(length) => write!(f, "set length {length} is shorter than its header"),
            Self::TemplateId(id) => write!(f, "template ID {id} is reserved"),
            Self::MessageLength(length) => {
                write!(f, "message length {length} is shorter than its header")
            }
            Self::ScopeFieldCount(count) => write!(f, "invalid scope field count {count}"),
            Self::AddressType(address_type) => write!(f, "unknown address type {address_type}"),
            Self::AsPathSegmentType(segment_type) => {
                write!(f, "unknown AS path segment type {segment_type}")
            }
            Self::Utf8 => write!(f, "string is not UTF-8"),
        }
    }
}

/// Why a packet could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// A value larger than its field on the wire holds.
    TooLarge { field: &'static str, value: usize },
    /// A value with no encoding in a field of `length` bytes, such as an
    /// integer too large for it.
    DoesNotFit { length: usize },
    /// A record whose number of values differs from its template's number
    /// of fields.
    Values { values: usize, fields: usize },
    /// An options template with option fields but no scope fields.
    NoScopeFields { template_id: u16 },
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { field, value } => write!(f, "{field} {value} does not fit its field"),
            Self::DoesNotFit { length } => {
                write!(f, "value does not fit a field of {length} bytes")
            }
            Self::Values { values, fields } => {
                write!(f, "record has {values} values for {fields} fields")
            }
            Self::NoScopeFields { template_id } => {
                write!(f, "options template {template_id} has no scope fields")
            }
        }
    }
}

impl error::Error for WriteError {}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Truncated(e) => Some(e),
            Self::Version(_)
            | Self::SetLength(_)
            | Self::TemplateId(_)
            | Self::MessageLength(_)
            | Self::ScopeFieldCount(_)
            | Self::AddressType(_)
            | Self::AsPathSegmentType(_)
            | Self::Utf8 => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display_their_cause() {
        let truncated = ParseError::from(Truncated {
            requested: 4,
            available: 1,
        });
        assert_eq!(truncated.to_string(), "truncated: needed 4 bytes, 1 left");
        assert_eq!(ParseError::Version(9).to_string(), "unexpected version 9");
        assert_eq!(
            ParseError::SetLength(3).to_string(),
            "set length 3 is shorter than its header"
        );
        assert_eq!(
            ParseError::TemplateId(0).to_string(),
            "template ID 0 is reserved"
        );
        assert_eq!(
            ParseError::MessageLength(15).to_string(),
            "message length 15 is shorter than its header"
        );
        assert_eq!(
            ParseError::ScopeFieldCount(0).to_string(),
            "invalid scope field count 0"
        );
        assert_eq!(
            ParseError::AddressType(3).to_string(),
            "unknown address type 3"
        );
        assert_eq!(
            ParseError::AsPathSegmentType(3).to_string(),
            "unknown AS path segment type 3"
        );
        assert_eq!(ParseError::Utf8.to_string(), "string is not UTF-8");
        assert_eq!(
            WriteError::TooLarge {
                field: "count",
                value: 65_536
            }
            .to_string(),
            "count 65536 does not fit its field"
        );
        assert_eq!(
            WriteError::DoesNotFit { length: 2 }.to_string(),
            "value does not fit a field of 2 bytes"
        );
        assert_eq!(
            WriteError::Values {
                values: 1,
                fields: 2
            }
            .to_string(),
            "record has 1 values for 2 fields"
        );
        assert_eq!(
            WriteError::NoScopeFields { template_id: 257 }.to_string(),
            "options template 257 has no scope fields"
        );
    }
}
