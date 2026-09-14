use std::io::{self, BufWriter, Write};

use rustflow_core::common::common_flow::CommonFlow;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::{FlowEncoder, RawEncoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;

/// Newline-delimited JSON, one object per record.
pub struct Ndjson {
    out: BufWriter<Writer>,
    names: Vec<String>,
    /// One record, written in a single call so a failed write leaves no
    /// partial line in the buffer.
    line: Vec<u8>,
}

/// The flow's fields and the enrichment fields in one object.
#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    flow: &'a CommonFlow,
    #[serde(flatten)]
    enriched: EnrichedMap<'a>,
}

struct EnrichedMap<'a> {
    names: &'a [String],
    values: &'a Enriched,
}

impl Serialize for EnrichedMap<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (name, value) in self.names.iter().zip(self.values.iter()) {
            if let Some(value) = value {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

fn write_line<T: Serialize + ?Sized>(
    out: &mut BufWriter<Writer>,
    line: &mut Vec<u8>,
    value: &T,
) -> io::Result<()> {
    line.clear();
    serde_json::to_writer(&mut *line, value)?;
    line.push(b'\n');
    out.write_all(line)
}

impl FlowEncoder for Ndjson {
    const EXTENSION: &'static str = "ndjson";

    fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            names: enriched_fields.to_vec(),
            line: Vec::with_capacity(1024),
        })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let row = Row {
            flow,
            enriched: EnrichedMap {
                names: &self.names,
                values: enriched,
            },
        };
        write_line(&mut self.out, &mut self.line, &row)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl RawEncoder for Ndjson {
    fn write_value<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        write_line(&mut self.out, &mut self.line, value)
    }
}
