//! Parsers for flow protocol datagrams.

use std::sync::Arc;
use std::{error, fmt};

use rustflow_reader::Truncated;

use crate::value::Value;

mod iana;
pub mod information_element;
pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
pub mod value;

/// The records of a data set, with the template they were decoded by.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSet<T> {
    pub template: Arc<T>,
    /// Each record's values, in template order: for options data, the scope
    /// values first.
    pub records: Vec<Vec<Value>>,
}

/// Why a datagram could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
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
}

impl From<Truncated> for Error {
    fn from(e: Truncated) -> Self {
        Self::Truncated(e)
    }
}

impl fmt::Display for Error {
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
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Truncated(e) => Some(e),
            Self::Version(_)
            | Self::SetLength(_)
            | Self::TemplateId(_)
            | Self::MessageLength(_)
            | Self::ScopeFieldCount(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display_their_cause() {
        let truncated = Error::from(Truncated {
            requested: 4,
            available: 1,
        });
        assert_eq!(truncated.to_string(), "truncated: needed 4 bytes, 1 left");
        assert_eq!(Error::Version(9).to_string(), "unexpected version 9");
        assert_eq!(
            Error::SetLength(3).to_string(),
            "set length 3 is shorter than its header"
        );
        assert_eq!(
            Error::TemplateId(0).to_string(),
            "template ID 0 is reserved"
        );
        assert_eq!(
            Error::MessageLength(15).to_string(),
            "message length 15 is shorter than its header"
        );
        assert_eq!(
            Error::ScopeFieldCount(0).to_string(),
            "invalid scope field count 0"
        );
    }
}
