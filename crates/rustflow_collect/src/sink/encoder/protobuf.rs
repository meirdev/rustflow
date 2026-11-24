use std::io::{self, BufWriter, Write};
use std::net::IpAddr;

use prost::encoding::{WireType, encode_key, encode_varint};
use rustflow_core::common_flow::{CommonFlow, FlowType};

use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;
use crate::field::Scalar;
use crate::schema::{Column, Schema};

/// The value of `rustflow.FlowType` in `proto/rustflow.proto`.
fn flow_type_number(flow_type: FlowType) -> u64 {
    match flow_type {
        FlowType::NetflowV5 => 1,
        FlowType::NetflowV9 => 2,
        FlowType::Ipfix => 3,
        FlowType::SflowV5 => 4,
    }
}

fn encode_number(buf: &mut Vec<u8>, number: u32, value: u64) {
    encode_key(number, WireType::Varint, buf);
    encode_varint(value, buf);
}

fn encode_bytes(buf: &mut Vec<u8>, number: u32, value: &[u8]) {
    encode_key(number, WireType::LengthDelimited, buf);
    encode_varint(value.len() as u64, buf);
    buf.extend_from_slice(value);
}

/// Appends `value` as the field `number`, in the wire form of its type in
/// `rustflow.proto`.
fn encode_field(buf: &mut Vec<u8>, number: u32, value: Scalar<'_>) {
    match value {
        Scalar::Unsigned(v) => encode_number(buf, number, v),
        // int64: negative values as their two's complement.
        Scalar::Timestamp(v) => encode_number(buf, number, v as u64),
        // sint64: zigzag, so that small negative numbers stay short.
        Scalar::Signed(v) => encode_number(buf, number, ((v << 1) ^ (v >> 63)) as u64),
        Scalar::Boolean(v) => encode_number(buf, number, v.into()),
        Scalar::FlowType(v) => encode_number(buf, number, flow_type_number(v)),
        Scalar::Float(v) => {
            encode_key(number, WireType::SixtyFourBit, buf);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        Scalar::String(v) => encode_bytes(buf, number, v.as_bytes()),
        Scalar::Octets(v) => encode_bytes(buf, number, v),
        Scalar::Address(IpAddr::V4(v)) => encode_bytes(buf, number, &v.octets()),
        Scalar::Address(IpAddr::V6(v)) => encode_bytes(buf, number, &v.octets()),
        Scalar::Mac(v) => encode_bytes(buf, number, &v.octets()),
    }
}

/// Length-delimited protobuf, one `rustflow.CommonFlow` per record: each
/// column that has a value, under its field number.
pub struct Protobuf {
    out: BufWriter<Writer>,
    columns: Vec<Column>,
    /// One message, written in a single call.
    buf: Vec<u8>,
    length: Vec<u8>,
}

impl Protobuf {
    pub fn open(out: Writer, schema: &Schema) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            columns: schema.columns().to_vec(),
            buf: Vec::with_capacity(512),
            length: Vec::with_capacity(4),
        })
    }
}

impl Encoder for Protobuf {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.buf.clear();
        for column in &self.columns {
            match column.value(flow, enriched) {
                // The required fields have no presence in proto3: a zero
                // is the default, and is not written.
                Some(Scalar::Unsigned(0) | Scalar::Timestamp(0)) if column.required => {}
                Some(value) => encode_field(&mut self.buf, column.number, value),
                None => {}
            }
        }
        self.length.clear();
        encode_varint(self.buf.len() as u64, &mut self.length);
        self.out.write_all(&self.length)?;
        self.out.write_all(&self.buf)
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

    use prost::Message;
    use rustflow_core::value::Value;

    use super::*;
    use crate::field::{self, Field, Kind};

    /// Some of the flow's fields and the added fields of the test, as a
    /// consumer would declare them.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct Consumer {
        #[prost(int32, tag = "1")]
        flow_type: i32,
        #[prost(int64, tag = "2")]
        time_received_ns: i64,
        #[prost(bytes = "vec", tag = "3")]
        sampler_address: Vec<u8>,
        #[prost(uint32, tag = "4")]
        sequence_num: u32,
        #[prost(uint32, optional, tag = "16")]
        src_port: Option<u32>,
        #[prost(uint32, optional, tag = "17")]
        dst_port: Option<u32>,
        #[prost(uint64, optional, tag = "1000")]
        count: Option<u64>,
        #[prost(sint64, optional, tag = "1001")]
        delta: Option<i64>,
        #[prost(double, optional, tag = "1002")]
        ratio: Option<f64>,
        #[prost(bool, optional, tag = "1003")]
        ok: Option<bool>,
        #[prost(int64, optional, tag = "2000")]
        start: Option<i64>,
        #[prost(bytes = "vec", optional, tag = "1004")]
        host: Option<Vec<u8>>,
        #[prost(string, optional, tag = "1005")]
        missing: Option<String>,
        #[prost(string, optional, tag = "1006")]
        site: Option<String>,
    }

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
    fn added_fields_are_fields_of_the_message() {
        let field = |name: &str, kind, number| Field {
            name: name.into(),
            kind,
            number,
        };
        let schema = Schema::new(
            &[
                field("count", Kind::U64, None),
                field("delta", Kind::I64, None),
                field("ratio", Kind::F64, None),
                field("ok", Kind::Boolean, None),
                field("start", Kind::Timestamp, Some(2000)),
                field("host", Kind::Address, None),
                field("missing", Kind::Text, None),
            ],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        let memory = Memory::default();
        let mut protobuf = Protobuf::open(Box::new(memory.clone()), &schema).unwrap();
        let mut flow = CommonFlow::new(FlowType::Ipfix, 0, [192, 0, 2, 1].into(), 9);
        flow.src_port = Some(0);
        flow.extra = vec![
            Some(Value::Unsigned32(7)),
            Some(Value::Signed32(-3)),
            Some(Value::Float64(0.5)),
            Some(Value::Boolean(true)),
            Some(Value::DateTimeSeconds(2)),
            Some(Value::Ipv4Address([192, 0, 2, 7].into())),
            None,
        ]
        .into();
        let enriched = vec![Some(field::Value::Text("lab".into()))];
        protobuf.encode(&flow, &enriched).unwrap();
        protobuf.finish().unwrap();

        let written = memory.0.lock().unwrap();
        let message = Consumer::decode_length_delimited(written.as_slice()).unwrap();
        assert_eq!(
            message,
            Consumer {
                flow_type: 3,
                time_received_ns: 0,
                sampler_address: vec![192, 0, 2, 1],
                sequence_num: 9,
                src_port: Some(0),
                dst_port: None,
                count: Some(7),
                delta: Some(-3),
                ratio: Some(0.5),
                ok: Some(true),
                start: Some(2_000_000_000),
                host: Some(vec![192, 0, 2, 7]),
                missing: None,
                site: Some("lab".into()),
            }
        );
    }
}
