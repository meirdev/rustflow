use std::io::{self, BufWriter, Write};

use rustflow_core::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::text::Text;
use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// Comma-separated values with a header row: the flow's columns followed by
/// the enrichment fields.
pub struct Csv {
    out: BufWriter<Writer>,
    /// One record, written in a single call so a failed write leaves no
    /// partial record behind.
    record: Vec<u8>,
}

macro_rules! field {
    ($record:ident, required, $value:expr) => {
        $value.write_text($record);
    };
    ($record:ident, optional, $value:expr) => {
        if let Some(value) = $value {
            value.write_text($record);
        }
    };
}

macro_rules! flow_fields {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        const HEADERS: &[&str] = &[$( stringify!($name), )*];

        /// Writes the flow's fields, each followed by a comma.
        fn write_flow(record: &mut Vec<u8>, flow: &CommonFlow) {
            let CommonFlow { $( $name, )* } = flow;
            $(
                field!(record, $presence, $name);
                record.push(b',');
            )*
        }
    };
}
for_each_flow_field!(flow_fields);

/// Writes `value` followed by a comma, quoted when it holds a delimiter, a
/// quote or a line break.
fn write_field(record: &mut Vec<u8>, value: &str) {
    if value.contains([',', '"', '\n', '\r']) {
        record.push(b'"');
        record.extend_from_slice(value.replace('"', "\"\"").as_bytes());
        record.push(b'"');
    } else {
        record.extend_from_slice(value.as_bytes());
    }
    record.push(b',');
}

impl Csv {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        let mut csv = Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            record: Vec::with_capacity(1024),
        };
        let names = HEADERS.iter().copied();
        for name in names.chain(enriched_fields.iter().map(String::as_str)) {
            write_field(&mut csv.record, name);
        }
        csv.write_record()?;
        Ok(csv)
    }

    /// Replaces the last field's comma with the line end, moves the record
    /// to `out`, and starts the next.
    fn write_record(&mut self) -> io::Result<()> {
        if let Some(last) = self.record.last_mut() {
            *last = b'\n';
        }
        let written = self.out.write_all(&self.record);
        self.record.clear();
        written
    }
}

impl Encoder for Csv {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        write_flow(&mut self.record, flow);
        for value in enriched.iter() {
            write_field(&mut self.record, value.as_deref().unwrap_or(""));
        }
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

    use rustflow_core::common_flow::FlowType;

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
        let flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 0);
        // A value that needs quoting.
        let enriched = vec![Some(Arc::from("a,\"b\""))];

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
            assert_eq!(&row[columns - 1], "a,\"b\"");
            rows += 1;
        }
        assert!(failed > 0);
        assert_eq!(rows + failed, 15_000);
    }
}
