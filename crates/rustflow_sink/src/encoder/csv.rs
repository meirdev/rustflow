use std::io;

use rustflow_core::common::common_flow::CommonFlow;

use super::text::{AddrText, flow_type_name};
use super::{FlowEncoder, Output, WRITE_BUFFER_BYTES};
use crate::flow::Enriched;
use crate::flow::fields::{self, Value};

/// Comma-separated values with a header row: the flow's columns followed by
/// the enrichment fields.
pub struct Csv {
    out: csv::Writer<Output>,
    /// Reused for formatting one field; never reallocates after warm-up.
    scratch: String,
}

/// The text form of one value. `None` leaves the field empty.
///
/// Integers go through `itoa` and addresses through [`AddrText`]: the
/// generic formatter was the largest cost in this encoder's profile.
fn write_text(scratch: &mut String, value: Value) {
    scratch.clear();
    let mut digits = itoa::Buffer::new();
    match value {
        Value::FlowType(v) => scratch.push_str(flow_type_name(v)),
        Value::Ip(Some(v)) => scratch.push_str(AddrText::ip(v).as_str()),
        Value::Mac(Some(v)) => scratch.push_str(AddrText::mac(v).as_str()),
        Value::U8(Some(v)) => scratch.push_str(digits.format(v)),
        Value::U16(Some(v)) => scratch.push_str(digits.format(v)),
        Value::U32(Some(v)) => scratch.push_str(digits.format(v)),
        Value::U64(Some(v)) => scratch.push_str(digits.format(v)),
        Value::TimestampNs(Some(v)) => scratch.push_str(digits.format(v)),
        Value::U8(None)
        | Value::U16(None)
        | Value::U32(None)
        | Value::U64(None)
        | Value::TimestampNs(None)
        | Value::Ip(None)
        | Value::Mac(None) => {}
    }
}

impl FlowEncoder for Csv {
    const EXTENSION: &'static str = "csv";

    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self> {
        let mut w = csv::WriterBuilder::new()
            .buffer_capacity(WRITE_BUFFER_BYTES)
            .from_writer(out);
        let names = fields::columns().map(|c| c.name);
        w.write_record(names.chain(enriched_fields.iter().map(String::as_str)))?;
        Ok(Self {
            out: w,
            scratch: String::new(),
        })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let Self { out, scratch } = self;
        // Each field goes straight from the scratch buffer into the csv
        // writer's buffer; there is no Vec<String> in between.
        fields::visit(flow, |_, value| {
            write_text(scratch, value);
            out.write_field(scratch.as_bytes())
        })?;
        for value in enriched.iter() {
            out.write_field(value.unwrap_or(""))?;
        }
        // Terminates the record started by write_field.
        out.write_record(None::<&[u8]>)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{SharedBuf, sample_flow};

    const FLOW_COLUMNS: usize = 37;

    fn rows(names: &[&str], flows: &[(CommonFlow, Enriched)]) -> Vec<Vec<String>> {
        let buf = SharedBuf::default();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut encoder = Csv::open(buf.boxed(), &names).unwrap();
        for (flow, enriched) in flows {
            encoder.encode(flow, enriched).unwrap();
        }
        encoder.finish().unwrap();

        let bytes = buf.contents();
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(bytes.as_slice());
        reader
            .records()
            .map(|r| r.unwrap().iter().map(str::to_string).collect())
            .collect()
    }

    #[test]
    fn record_matches_the_header_width() {
        let mut enriched = Enriched::new(2);
        enriched.set(0, "13335");
        let rows = rows(&["src_asn", "src_org"], &[(sample_flow(), enriched)]);

        let header = &rows[0];
        let row = &rows[1];
        assert_eq!(header.len(), FLOW_COLUMNS + 2);
        assert_eq!(header[0], "flow_type");
        assert_eq!(header[FLOW_COLUMNS], "src_asn");
        assert_eq!(header[FLOW_COLUMNS + 1], "src_org");

        assert_eq!(row.len(), header.len());
        assert_eq!(row[0], "IPFIX");
        assert_eq!(row[7], "1234");
        // an absent optional field stays empty
        assert_eq!(row[10], "");
        assert_eq!(row[FLOW_COLUMNS], "13335");
        // an enrichment field with no value stays empty
        assert_eq!(row[FLOW_COLUMNS + 1], "");
    }

    #[test]
    fn values_do_not_leak_between_flows() {
        let mut second = sample_flow();
        second.src_addr = None;
        second.bytes = 7;
        let rows = rows(
            &[],
            &[
                (sample_flow(), Enriched::new(0)),
                (second, Enriched::new(0)),
            ],
        );
        assert_eq!(rows[1][9], "10.1.2.3");
        assert_eq!(rows[2][9], "", "stale value from the previous record");
        assert_eq!(rows[2][7], "7");
    }
}
