use std::io::{self, BufWriter, Write};

use rustflow_core::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::text::Text;
use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;
use crate::sink::schema::{Added, FlowFields, Schema};

/// Comma-separated values with a header row, one column for each of the
/// schema's.
pub struct Csv {
    out: BufWriter<Writer>,
    flow: FlowFields,
    /// The columns after the flow's fields.
    added: Vec<Added>,
    /// One record, written in a single call so a failed write leaves no
    /// partial record behind.
    record: Vec<u8>,
    /// A text value, before it is quoted into `record`.
    text: Vec<u8>,
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
        /// Writes the selected fields of the flow, each followed by a
        /// comma.
        fn write_flow(record: &mut Vec<u8>, flow: &CommonFlow, selected: FlowFields) {
            let [ $( $name, )* ] = selected;
            $(
                if $name {
                    field!(record, $presence, &flow.$name);
                    record.push(b',');
                }
            )*
        }
    };
}
for_each_flow_field!(flow_fields);

/// Writes `value` followed by a comma, quoted when it holds a delimiter, a
/// quote or a line break.
fn write_field(record: &mut Vec<u8>, value: &[u8]) {
    if value
        .iter()
        .any(|byte| matches!(byte, b',' | b'"' | b'\n' | b'\r'))
    {
        record.push(b'"');
        for &byte in value {
            if byte == b'"' {
                record.push(b'"');
            }
            record.push(byte);
        }
        record.push(b'"');
    } else {
        record.extend_from_slice(value);
    }
    record.push(b',');
}

impl Csv {
    pub fn open(out: Writer, schema: &Schema) -> io::Result<Self> {
        let mut csv = Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            flow: schema.flow_fields(),
            added: schema.added().map(|(_, added)| added).collect(),
            record: Vec::with_capacity(1024),
            text: Vec::new(),
        };
        for (name, _) in schema.columns() {
            write_field(&mut csv.record, name.as_bytes());
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
        let record = &mut self.record;
        write_flow(record, flow, self.flow);
        for added in &self.added {
            let text = &mut self.text;
            text.clear();
            if let Some(value) = added.value(flow, enriched) {
                value.write_text(text);
            }
            write_field(record, text);
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
    use crate::field::{Field, Kind, Value};

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
    fn only_the_selected_columns_are_written() {
        let site = Field {
            name: "site".into(),
            kind: Kind::Text,
            number: None,
        };
        let names = ["site", "sequence_num", "flow_type", "bytes"].map(String::from);
        let schema = Schema::new(&[], &[site]).unwrap().select(&names).unwrap();
        let disk = Disk::default();
        let mut csv = Csv::open(Box::new(disk.clone()), &schema).unwrap();
        let flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 7);
        csv.encode(&flow, &vec![Some(Value::Text("lab".into()))])
            .unwrap();
        csv.finish().unwrap();

        let written = disk.written.lock().unwrap();
        assert_eq!(
            std::str::from_utf8(&written).unwrap(),
            "flow_type,sequence_num,bytes,site\nIPFIX,7,,lab\n"
        );
    }

    #[test]
    fn a_failed_write_loses_whole_records_only() {
        let disk = Disk::default();
        let site = Field {
            name: "site".into(),
            kind: Kind::Text,
            number: None,
        };
        let schema = Schema::new(&[], &[site]).unwrap();
        let mut csv = Csv::open(Box::new(disk.clone()), &schema).unwrap();
        let flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 0);
        // A value that needs quoting.
        let enriched = vec![Some(Value::Text("a,\"b\"".into()))];

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
