pub mod data;
pub mod message;
pub mod template;

pub use message::IpfixMessage;

// Re-export InformationElement from core
pub use rustflow_core::common::InformationElement;

// IPFIX Protocol Constants
pub const IPFIX_VERSION: u16 = 10;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

// Exporter-specific Template IDs (chosen by this exporter)
pub const FLOW_TEMPLATE_ID: u16 = 256;
pub const OPTIONS_TEMPLATE_ID: u16 = 257;
