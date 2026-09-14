use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::{self, BufWriter, Write};

use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::{FlowEncoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// Comma-separated values with a header row: the flow's columns followed by
/// the enrichment fields.
pub struct Csv {
    /// The csv buffer holds one record, handed to the `BufWriter` in a
    /// single write after each record, so a failed write leaves no partial
    /// record behind.
    out: csv::Writer<Batched>,
    scratch: String,
}

/// Room for one record plus those retained across a failed write.
const RECORD_BUFFER_BYTES: usize = 64 * 1024;

/// `csv::Writer::flush` also flushes the writer beneath it, which would be
/// a system call per record; this one ignores that and is flushed by
/// [`Csv::flush`] through `get_ref`, hence the `RefCell`.
struct Batched(RefCell<BufWriter<Writer>>);

impl Write for Batched {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.get_mut().write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
            out: &mut csv::Writer<Batched>,
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

    fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        let out = Batched(RefCell::new(BufWriter::with_capacity(
            WRITE_BUFFER_BYTES,
            out,
        )));
        let mut w = csv::WriterBuilder::new()
            .buffer_capacity(RECORD_BUFFER_BYTES)
            .from_writer(out);
        let names = HEADERS.iter().copied();
        w.write_record(names.chain(enriched_fields.iter().map(String::as_str)))?;
        w.flush()?;
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
        self.out.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()?;
        self.out.get_ref().0.borrow_mut().flush()
    }

    fn finish(mut self) -> io::Result<()> {
        self.flush()
    }
}
