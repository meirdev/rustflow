use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::{self, BufWriter, Write};

use rustflow_core::convert::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// Comma-separated values with a header row: the flow's columns followed by
/// the enrichment fields.
pub struct Csv {
    out: BufWriter<Writer>,
    /// One record at a time, encoded in memory, where it cannot fail, and
    /// handed to `out` in a single write, so a failed write leaves no
    /// partial record behind.
    record: csv::Writer<Record>,
    scratch: String,
}

/// Where the csv writer encodes a record. `csv::Writer` hands out no `&mut`
/// to it, so it is read and cleared through `get_ref`, hence the `RefCell`.
#[derive(Default)]
struct Record(RefCell<Vec<u8>>);

impl Write for Record {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.get_mut().extend_from_slice(data);
        Ok(data.len())
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
            out: &mut csv::Writer<Record>,
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

impl Csv {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        let mut csv = Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            record: csv::Writer::from_writer(Record::default()),
            scratch: String::new(),
        };
        let names = HEADERS.iter().copied();
        csv.record
            .write_record(names.chain(enriched_fields.iter().map(String::as_str)))?;
        csv.write_record()?;
        Ok(csv)
    }

    /// Moves the record encoded so far to `out`, and starts the next.
    fn write_record(&mut self) -> io::Result<()> {
        self.record.flush()?;
        let mut record = self.record.get_ref().0.borrow_mut();
        let written = self.out.write_all(&record);
        record.clear();
        written
    }
}

impl Encoder for Csv {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        write_flow(&mut self.record, &mut self.scratch, flow)?;
        for value in enriched.iter() {
            self.record.write_field(value.as_deref().unwrap_or(""))?;
        }
        // Terminates the record started by write_field.
        self.record.write_record(None::<&[u8]>)?;
        self.write_record()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(&mut self) -> io::Result<()> {
        self.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use rustflow_core::protocol::Protocol;

    use super::*;

    /// A disk that can be made to fail, keeping what reached it.
    #[derive(Clone, Default)]
    struct Disk {
        written: Arc<Mutex<Vec<u8>>>,
        full: Arc<AtomicBool>,
    }

    impl Write for Disk {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.full.load(Ordering::Relaxed) {
                return Err(io::Error::other("disk full"));
            }
            self.written.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_write_loses_whole_records_only() {
        let disk = Disk::default();
        let mut csv = Csv::open(Box::new(disk.clone()), &["site".to_string()]).unwrap();
        let flow = CommonFlow::new(Protocol::Ipfix);
        // A value that needs quoting.
        let enriched = vec![Some(Arc::from("a,b"))];

        let mut failed = 0;
        for i in 0..15_000 {
            disk.full
                .store((5_000..10_000).contains(&i), Ordering::Relaxed);
            if csv.encode(&flow, &enriched).is_err() {
                failed += 1;
            }
        }
        csv.finish().unwrap();

        let written = disk.written.lock().unwrap();
        let mut reader = csv::Reader::from_reader(written.as_slice());
        let columns = reader.headers().unwrap().len();
        let mut rows = 0;
        for row in reader.records() {
            let row = row.unwrap();
            assert_eq!(row.len(), columns);
            assert_eq!(&row[columns - 1], "a,b");
            rows += 1;
        }
        assert!(failed > 0);
        assert_eq!(rows + failed, 15_000);
    }
}
