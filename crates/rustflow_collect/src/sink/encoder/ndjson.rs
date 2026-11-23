use std::io::{self, BufWriter, Write};

use rustflow_core::common_flow::CommonFlow;
use rustflow_core::for_each_flow_field;

use super::text::Text;
use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;
use crate::field::Scalar;
use crate::sink::schema::{Added, Schema};

/// Newline-delimited JSON, one object per record, with a member for each
/// of the schema's columns that has a value.
pub struct Ndjson {
    out: BufWriter<Writer>,
    /// The columns after the flow's fields, each with its `,"name":`.
    added: Vec<(Vec<u8>, Added)>,
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

fn write_added(line: &mut Vec<u8>, key: &[u8], value: Scalar<'_>) -> io::Result<()> {
    match value {
        // JSON has no NaN or infinity.
        Scalar::Float(v) if !v.is_finite() => return Ok(()),
        Scalar::String(v) => {
            line.extend_from_slice(key);
            serde_json::to_writer(&mut *line, v)?;
        }
        Scalar::Unsigned(_)
        | Scalar::Signed(_)
        | Scalar::Float(_)
        | Scalar::Boolean(_)
        | Scalar::Timestamp(_) => {
            line.extend_from_slice(key);
            value.write_text(line);
        }
        // Addresses and hex need no escaping.
        Scalar::Address(_) | Scalar::Mac(_) | Scalar::Octets(_) => {
            line.extend_from_slice(key);
            line.push(b'"');
            value.write_text(line);
            line.push(b'"');
        }
    }
    Ok(())
}

impl Ndjson {
    pub fn open(out: Writer, schema: &Schema) -> io::Result<Self> {
        let added = schema
            .added()
            .map(|(name, added)| {
                let key = format!(",{}:", serde_json::to_string(name)?).into_bytes();
                Ok((key, added))
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            added,
            line: Vec::with_capacity(1024),
        })
    }
}

impl Encoder for Ndjson {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let line = &mut self.line;
        line.clear();
        write_flow(line, flow);
        for (key, added) in &self.added {
            if let Some(value) = added.value(flow, enriched) {
                write_added(line, key, value)?;
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rustflow_core::common_flow::FlowType;
    use rustflow_core::value::Value;

    use super::*;
    use crate::field::{self, Field, Kind};

    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<Vec<u8>>>);

    impl Write for Memory {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn added_members_are_written_when_they_have_a_value() {
        let field = |name: &str, kind| Field {
            name: name.into(),
            kind,
            number: None,
        };
        let schema = Schema::new(
            &[
                field("name", Kind::Text),
                field("ratio", Kind::Float),
                field("missing", Kind::Unsigned),
                field("host", Kind::Text),
            ],
            &[field("asn", Kind::Unsigned), field("site", Kind::Text)],
        )
        .unwrap();
        let memory = Memory::default();
        let mut ndjson = Ndjson::open(Box::new(memory.clone()), &schema).unwrap();
        let mut flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 0);
        flow.extra = vec![
            Some(Value::String("a \"b\"".into())),
            Some(Value::Float64(f64::NAN)),
            None,
            Some(Value::Ipv4Address([192, 0, 2, 7].into())),
        ]
        .into();
        let enriched = vec![Some(field::Value::Unsigned(64512)), None];
        ndjson.encode(&flow, &enriched).unwrap();
        ndjson.finish().unwrap();

        let written = memory.0.lock().unwrap();
        let line: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(line["name"], "a \"b\"");
        assert_eq!(line["host"], "192.0.2.7");
        assert!(line.get("ratio").is_none());
        assert!(line.get("missing").is_none());
        assert_eq!(line["asn"], 64512);
        assert!(line.get("site").is_none());
    }
}
