//! Flow protocol packets: NetFlow v5, NetFlow v9, IPFIX and sFlow v5, parsed
//! from datagrams and written back.
//!
//! NetFlow v9 and IPFIX describe their records by templates of information
//! elements; [`information_element`] and [`value`] serve those two alone. A
//! parsed record is its values in template order, the template saying what
//! each one is.

pub use error::{ParseError, WriteError};
pub use record::DataSet;

mod error;
#[cfg(test)]
mod fixtures;
pub mod information_element;
pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
mod record;
pub mod sflow_v5;
mod template_cache;
pub mod value;
