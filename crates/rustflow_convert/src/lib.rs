//! The Conversion Process of an IPFIX Mediator (RFC 6183 section
//! 5.3.2.1): flow records of NetFlow v5, NetFlow v9, IPFIX and sFlow v5
//! turned into records of IPFIX information elements, whatever protocol
//! they arrived in.
//!
//! Every record converted carries what a later stage needs without the
//! packet it came in: absolute times, the exporter that sent it, when it
//! was received, and how its packets were sampled.

pub use record::{Protocol, Received, Record};

mod domain;
#[cfg(test)]
mod fixtures;
pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
mod packet_section;
mod record;
mod sampling;
pub mod sflow_v5;
mod templated;
mod time;
