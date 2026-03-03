//! # RustFlow
//!
//! A high-performance flow collector library for NetFlow, IPFIX, and sFlow.
//!
//! ## Quick Start (Sync)
//!
//! ```no_run
//! use rustflow::{NetflowReader, SflowReader};
//!
//! // Read NetFlow/IPFIX data
//! let reader = NetflowReader::bind("0.0.0.0:9995").unwrap();
//! for flow in reader {
//!     println!("{:?}", flow.unwrap());
//! }
//!
//! // Or read sFlow data
//! let reader = SflowReader::bind("0.0.0.0:6343").unwrap();
//! for flow in reader {
//!     println!("{:?}", flow.unwrap());
//! }
//! ```
//!
//! ## Async Support (with `tokio` feature)
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # async fn example() {
//! use rustflow::tokio::{NetflowReader, SflowReader};
//!
//! let mut reader = NetflowReader::bind("0.0.0.0:9995").await.unwrap();
//! loop {
//!     let flow = reader.read().await.unwrap();
//!     println!("{:?}", flow);
//! }
//! # }
//! ```

mod processor;
mod reader;

#[cfg(feature = "tokio")]
mod async_reader;

mod pcap_reader;

pub use processor::{NetflowPacket, NetflowProcessor, SflowPacket, SflowProcessor};
pub use reader::{NetflowReadResult, NetflowReader, SflowReadResult, SflowReader};

pub mod pcap {
    //! Readers for pcap files.
    pub use crate::pcap_reader::{NetflowPcapReader, SflowPcapReader};
}

#[cfg(feature = "tokio")]
pub mod tokio {
    //! Async readers using Tokio runtime.
    pub use crate::async_reader::{NetflowReader, SflowReader};
}

pub use rustflow_core::common::common_flow::CommonFlow;
pub use rustflow_core::common::ie_registry::IERegistry;

pub mod ipfix {
    pub use rustflow_core::ipfix::parser::{
        DataRecord, FieldSpecifier, FieldValue, Header, IpfixPacket, IpfixParser,
        OptionsTemplateRecord, Record, Set, TemplateRecord,
    };
}

pub mod netflow_v5 {
    pub use rustflow_core::netflow_v5::parser::{FlowRecord, Header, NetFlowV5Packet};
}

pub mod netflow_v9 {
    pub use rustflow_core::netflow_v9::parser::{
        DataRecord, FlowSet, Header, NetFlowV9Packet, NetflowV9Parser, Record, TemplateRecord,
    };
}

pub mod sflow {
    pub use rustflow_core::sflow_v5::parser::{
        ExpandedFlowSample, FlowSample, SFlowV5, Sample, SflowV5Parser,
    };
}
