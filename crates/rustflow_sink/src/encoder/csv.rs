use std::fmt::Write as _;
use std::io;

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::{FlowEncoder, Output, WRITE_BUFFER_BYTES};
use crate::enriched::Enriched;

/// Comma-separated values with a header row: the flow's columns followed by
/// the enrichment fields.
pub struct Csv {
    out: csv::Writer<Output>,
    scratch: String,
}

macro_rules! text {
    ($scratch:expr, required, $value:expr) => {
        let _ = write!($scratch, "{}", $value);
    };
    ($scratch:expr, optional, $value:expr) => {
        if let Some(value) = $value {
            let _ = write!($scratch, "{value}");
        }
    };
}

macro_rules! flow_fields {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        const HEADERS: &[&str] = &[$( stringify!($name), )*];

        fn write_flow(
            out: &mut csv::Writer<Output>,
            scratch: &mut String,
            flow: &CommonFlow,
        ) -> io::Result<()> {
            let CommonFlow { $( $name, )* } = flow;
            $(
                scratch.clear();
                text!(scratch, $presence, $name);
                out.write_field(scratch.as_bytes())?;
            )*
            Ok(())
        }
    };
}
for_each_flow_field!(flow_fields);

impl FlowEncoder for Csv {
    const EXTENSION: &'static str = "csv";

    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self> {
        let mut w = csv::WriterBuilder::new()
            .buffer_capacity(WRITE_BUFFER_BYTES)
            .from_writer(out);
        let names = HEADERS.iter().copied();
        w.write_record(names.chain(enriched_fields.iter().map(String::as_str)))?;
        Ok(Self {
            out: w,
            scratch: String::new(),
        })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        write_flow(&mut self.out, &mut self.scratch, flow)?;
        for value in enriched.iter() {
            self.out.write_field(value.unwrap_or(""))?;
        }
        // Terminates the record started by write_field.
        self.out.write_record(None::<&[u8]>)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}
