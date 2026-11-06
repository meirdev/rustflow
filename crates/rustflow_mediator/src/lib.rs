//! An IPFIX Mediator (RFC 6183): Collecting Processes receive records,
//! Intermediate Processes transform them, Exporting Processes send them
//! on.
//!
//! A pipeline is a graph of named components, each of a `type`, processes
//! and exporters fed by the components their `inputs` name:
//!
//! ```toml
//! [collectors.netflow]
//! type = "netflow"
//! listen = ":9995"
//!
//! [processes.names]
//! type = "correlation"
//! inputs = ["netflow"]
//! file = "ifnames.csv"
//!
//! [processes.tcp]
//! type = "selection"
//! inputs = ["names"]
//! condition = "protocolIdentifier == 6"
//!
//! [meters.eth0]
//! type = "capture"
//! interface = "eth0"
//!
//! [exporters.parquet]
//! type = "parquet"
//! inputs = ["tcp", "eth0"]
//! path = "/var/lib/rustflow"
//!
//! [exporters.upstream]
//! type = "ipfix"
//! inputs = ["names"]            # every enriched record, not only TCP
//! address = "10.0.0.5:4739"
//! ```
//!
//! What flows is [`Item`]s: records in the IPFIX information model, and the
//! control information a collector knows besides them. A [`Process`]
//! turns items into items and nothing else, so processes compose in any
//! order and test alone; an [`Exporter`] takes what reaches it. A
//! [`Registry`] maps each process and exporter `type` to its constructor,
//! so an embedding program decides which exist, and anything implementing
//! the traits can be one. Records come from two kinds of source. Collectors
//! are the program's own: it runs each one its configuration names and
//! pushes what it receives into the pipeline under that name. Meters are
//! Metering Processes (RFC 5470): a [`Meter`] makes records itself, from
//! packets captured on an interface or from nothing at all, and the
//! registry builds it like a process or an exporter.
//!
//! A [`Runner`] runs every meter, process and exporter on a thread of its
//! own, each handing what it emits to the inboxes of the components that
//! read it. Collectors push chunks of items through a [`Feed`] each; the
//! runner ticks every component on a schedule, and the stream ends once
//! every feed is gone.

pub use config::{Component, Config, Source};
pub use error::Error;
pub use exporter::Exporter;
pub use item::{Control, Item};
pub use meter::{Meter, Stop};
pub use pipeline::{Builder, Pipeline, SourceId};
pub use process::{Output, Process};
pub use registry::{Built, Registry};
pub use runner::{Closed, Feed, Runner, Schedule};
pub use rustflow_core::convert::{Received, Record};

mod config;
mod error;
mod exporter;
mod item;
mod meter;
mod pipeline;
mod process;
mod registry;
mod runner;
