//! Output sinks for `rustflow collect`.
//!
//! Three layers, each unaware of the ones above it:
//!
//! ```text
//!    pipeline::encoder_loop ──owns──> Box<dyn FlowSink>
//!                                          │
//!                                 sink::RotatingSink<E>       when to open / close / rename files
//!                                   │              │
//!                           sink::Destination    E: encoder::FlowEncoder   how to turn a flow into bytes
//!                          (where bytes go)            │
//!                                               Box<dyn Write + Send>
//! ```
//!
//! [`flow`] describes what a flow looks like to every encoder: the one
//! field list and the positional enrichment values.

pub mod encoder;
pub mod flow;
pub mod pipeline;
pub mod sink;

pub use encoder::{Csv, Discard, FlowEncoder, Ndjson, Parquet, Protobuf, RawEncoder};
pub use flow::Enriched;
pub use pipeline::{FLUSH_INTERVAL, encoder_loop};
pub use sink::{FlowSink, Format, OutputMetrics, RawSink, SinkConfig, build, build_raw};

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::{self, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use rustflow_core::common::common_flow::{CommonFlow, FlowType};

    /// A `Write` that tests can read back after the encoder consumed it.
    #[derive(Clone, Default)]
    pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        pub fn boxed(&self) -> Box<dyn Write + Send> {
            Box::new(self.clone())
        }

        pub fn contents(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }

        pub fn text(&self) -> String {
            String::from_utf8(self.contents()).unwrap()
        }
    }

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn sample_flow() -> CommonFlow {
        let mut flow = CommonFlow::new(FlowType::Ipfix);
        flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        flow.src_port = Some(443);
        flow.bytes = 1234;
        // dst_addr and most other fields stay None
        flow
    }
}
