use std::io::{self, BufWriter, Write};

use rustflow_core::common::common_flow::CommonFlow;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::{FlowEncoder, Output, RawEncoder, WRITE_BUFFER_BYTES};
use crate::enrich::Enriched;

/// Newline-delimited JSON, one object per record.
pub struct Ndjson {
    out: BufWriter<Output>,
    names: Vec<String>,
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

impl FlowEncoder for Ndjson {
    const EXTENSION: &'static str = "ndjson";

    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            names: enriched_fields.to_vec(),
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
        serde_json::to_writer(&mut self.out, &row)?;
        self.out.write_all(b"\n")
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
        serde_json::to_writer(&mut self.out, value)?;
        self.out.write_all(b"\n")
    }
}
