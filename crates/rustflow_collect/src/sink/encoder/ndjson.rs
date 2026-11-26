use std::io::{self, BufWriter, Write};

use rustflow_core::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::text::Text;
use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// Newline-delimited JSON, one object per record.
pub struct Ndjson {
    out: BufWriter<Writer>,
    /// `,"name":` for each enrichment field.
    keys: Vec<Vec<u8>>,
    /// One record, written in a single call so a failed write leaves no
    /// partial line in the buffer.
    line: Vec<u8>,
}

fn write_value<T: Text>(line: &mut Vec<u8>, value: &T) {
    if T::NUMERIC {
        value.write_text(line);
    } else {
        line.push(b'"');
        value.write_text(line);
        line.push(b'"');
    }
}

macro_rules! member {
    ($line:ident, $name:ident, required, $value:expr) => {
        $line.extend_from_slice(concat!(",\"", stringify!($name), "\":").as_bytes());
        write_value($line, $value);
    };
    ($line:ident, $name:ident, optional, $value:expr) => {
        if let Some(value) = $value {
            member!($line, $name, required, value);
        }
    };
}

macro_rules! flow_fields {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        /// Writes the flow's members, each preceded by a comma.
        fn write_flow(line: &mut Vec<u8>, flow: &CommonFlow) {
            let CommonFlow { $( $name, )* .. } = flow;
            $( member!(line, $name, $presence, $name); )*
        }
    };
}
for_each_flow_field!(flow_fields);

impl Ndjson {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        let keys = enriched_fields
            .iter()
            .map(|name| Ok(format!(",{}:", serde_json::to_string(name)?).into_bytes()))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            keys,
            line: Vec::with_capacity(1024),
        })
    }
}

impl Encoder for Ndjson {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let line = &mut self.line;
        line.clear();
        write_flow(line, flow);
        for (key, value) in self.keys.iter().zip(enriched.iter()) {
            if let Some(value) = value {
                line.extend_from_slice(key);
                serde_json::to_writer(&mut *line, &**value)?;
            }
        }
        // The flow's required fields always write the first member, so the
        // line starts with its comma.
        line[0] = b'{';
        line.extend_from_slice(b"}\n");
        self.out.write_all(line)
    }

    /// One write per line, so a failed write cannot leave half a line.
    fn write_raw(&mut self, lines: &[u8]) -> io::Result<()> {
        for line in lines.split_inclusive(|b| *b == b'\n') {
            self.out.write_all(line)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
