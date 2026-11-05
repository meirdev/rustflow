//! NetFlow v5, NetFlow v9, IPFIX and sFlow v5, from datagrams to records of
//! IPFIX information elements:
//!
//! - [`protocol`] parses the packets of each protocol and writes them back.
//! - [`dissect`] reads captured packets through link layers and tunnels to
//!   their IP and transport headers, as sFlow samples them.
//! - [`convert`] turns parsed packets into records of IPFIX information
//!   elements, whatever protocol they arrived in (RFC 6183 section 5.3.2.1).
//! - [`reader`] receives datagrams on a socket and gives back those records
//!   (RFC 6183 section 5.1).

mod bytes;
pub mod convert;
pub mod dissect;
#[cfg(test)]
mod fixtures;
pub mod protocol;
pub mod reader;
