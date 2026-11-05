//! The Collecting Process of an IPFIX Mediator (RFC 6183 section 5.1),
//! read from: NetFlow v5, NetFlow v9 and IPFIX datagrams on one socket, or
//! sFlow v5 on another, from any mix of exporters, as records of IPFIX
//! information elements. With the `pcap` feature, a [`PcapReader`] reads
//! them from a capture of the datagrams instead.
//!
//! Options records are records too, with the scope they describe, so
//! nothing an exporter says is lost. Flows alone are one adapter away:
//!
//! ```no_run
//! use rustflow_core_new::reader::{Family, Reader};
//!
//! let reader = Reader::bind("0.0.0.0:9995", Family::Netflow).unwrap();
//! for flow in reader.flows() {
//!     println!("{:?}", flow.unwrap());
//! }
//! ```
//!
//! With options records, and the latest of each kept for looking up:
//!
//! ```no_run
//! use rustflow_core_new::protocol::information_element::iana;
//! use rustflow_core_new::reader::{Family, Read, Reader};
//!
//! let mut reader = Reader::bind("0.0.0.0:9995", Family::Netflow).unwrap();
//! loop {
//!     match reader.read().unwrap() {
//!         Read::Record(record) if record.is_options() => {
//!             println!("options for {:?}: {:?}", record.scope, record);
//!         }
//!         Read::Record(flow) => {
//!             let names = reader.options().by_element(iana::INTERFACE_NAME);
//!             println!("{flow:?}, {} interface names known", names.count());
//!         }
//!         Read::Timeout => break,
//!         Read::Malformed { exporter, error } => eprintln!("{exporter}: {error}"),
//!     }
//! }
//! ```

pub use collector::Collector;
pub use options::OptionsTable;
#[cfg(feature = "pcap")]
pub use pcap::PcapReader;
pub use pending::{PendingLimits, PendingStats};
pub use read::{Flows, Read};
pub use socket::Reader;

pub use crate::convert::{Family, Protocol, Received, Record, Scope};

mod collector;
mod options;
#[cfg(feature = "pcap")]
mod pcap;
mod pending;
mod queue;
mod read;
mod socket;
