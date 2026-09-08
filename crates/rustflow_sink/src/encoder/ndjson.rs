use std::io::{self, BufWriter, Write};

use rustflow_core::common::common_flow::CommonFlow;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::{FlowEncoder, Output, RawEncoder, WRITE_BUFFER_BYTES};
use crate::flow::Enriched;

/// Newline-delimited JSON, one object per record.
pub struct Ndjson {
    out: BufWriter<Output>,
    names: Vec<String>,
}

/// One output line: the flow's own fields plus the enrichment fields,
/// flattened into a single object. `serde_json` streams `flatten` through
/// `serialize_map`, so there is no intermediate `Value` tree.
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
        if self.names.is_empty() {
            // Fast path: the struct serializes straight into the buffer.
            serde_json::to_writer(&mut self.out, flow)?;
        } else {
            let row = Row {
                flow,
                enriched: EnrichedMap {
                    names: &self.names,
                    values: enriched,
                },
            };
            serde_json::to_writer(&mut self.out, &row)?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{SharedBuf, sample_flow};

    fn encode(names: &[&str], enriched: &Enriched) -> String {
        let buf = SharedBuf::default();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut encoder = Ndjson::open(buf.boxed(), &names).unwrap();
        encoder.encode(&sample_flow(), enriched).unwrap();
        encoder.finish().unwrap();
        buf.text()
    }

    #[test]
    fn enriched_line_is_valid_json_with_the_extra_keys() {
        let mut enriched = Enriched::new(2);
        enriched.set(0, "13335");
        // a value that must be escaped, and would corrupt the object if spliced raw
        enriched.set(1, "Cloud \"Net\", Inc.\\x");

        let line = encode(&["src_asn", "src_org"], &enriched);

        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(value["src_asn"], "13335");
        assert_eq!(value["src_org"], "Cloud \"Net\", Inc.\\x");
        assert_eq!(value["src_port"], 443);
        assert_eq!(value["flow_type"], "IPFIX");
    }

    #[test]
    fn absent_enrichment_fields_are_omitted() {
        let line = encode(&["src_asn"], &Enriched::new(1));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(value.get("src_asn").is_none());
        assert!(value.get("dst_addr").is_none(), "None fields stay omitted");
    }

    #[test]
    fn flattened_row_is_byte_identical_to_the_plain_struct_when_nothing_matched() {
        // Today's output for a flow without enrichment is `to_writer(flow)`;
        // the flatten path must produce exactly the same bytes.
        let plain = encode(&[], &Enriched::new(0));
        let flattened = encode(&["src_asn"], &Enriched::new(1));
        assert_eq!(plain, flattened);
    }

    #[test]
    fn raw_values_are_one_json_document_per_line() {
        let buf = SharedBuf::default();
        let mut encoder = Ndjson::open(buf.boxed(), &[]).unwrap();
        encoder.write_value(&serde_json::json!({"a": 1})).unwrap();
        encoder.write_value(&[1, 2, 3]).unwrap();
        encoder.finish().unwrap();
        assert_eq!(buf.text(), "{\"a\":1}\n[1,2,3]\n");
    }
}
