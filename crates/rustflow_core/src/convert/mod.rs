//! The Conversion Process of an IPFIX Mediator (RFC 6183 section
//! 5.3.2.1): flow records of NetFlow v5, NetFlow v9, IPFIX and sFlow v5
//! turned into records of IPFIX information elements, whatever protocol
//! they arrived in.
//!
//! Every record converted carries what a later stage needs without the
//! packet it came in: absolute times, the exporter that sent it, when it
//! was received, and how its packets were sampled. Options records come
//! out as records too, with the scope they describe, after what they say
//! was applied to the flows that follow them.

pub use common_flow::{CommonFlow, Mapper, Mapping};
pub use record::{Elements, Received, Record, Scope};

mod common_flow;
pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
mod packet_fields;
mod record;
mod sampling;
pub mod sflow_v5;
pub(crate) mod templated;
mod time;
