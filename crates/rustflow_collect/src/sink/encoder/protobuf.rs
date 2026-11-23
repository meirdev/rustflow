use std::io::{self, BufWriter, Write};
use std::net::IpAddr;

use prost::Message;
use prost::encoding::{WireType, encode_key, encode_varint};
use rustflow_core::common_flow::{self, CommonFlow};

use super::{Encoder, WRITE_BUFFER_BYTES, Writer};
use crate::enrich::Enriched;
use crate::field::Scalar;
use crate::sink::schema::{Added, Schema};

/// `rustflow.FlowType` of `proto/rustflow.proto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ::prost::Enumeration)]
#[repr(i32)]
pub enum FlowType {
    Unspecified = 0,
    NetflowV5 = 1,
    NetflowV9 = 2,
    Ipfix = 3,
    SflowV5 = 4,
}

impl From<common_flow::FlowType> for FlowType {
    fn from(flow_type: common_flow::FlowType) -> Self {
        match flow_type {
            common_flow::FlowType::NetflowV5 => Self::NetflowV5,
            common_flow::FlowType::NetflowV9 => Self::NetflowV9,
            common_flow::FlowType::Ipfix => Self::Ipfix,
            common_flow::FlowType::SflowV5 => Self::SflowV5,
        }
    }
}

/// `rustflow.CommonFlow` of `proto/rustflow.proto`: the fields of
/// `CommonFlow`, tagged in its order.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowMessage {
    #[prost(enumeration = "FlowType", tag = "1")]
    pub flow_type: i32,
    #[prost(int64, tag = "2")]
    pub time_received_ns: i64,
    #[prost(bytes = "vec", tag = "3")]
    pub sampler_address: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub sequence_num: u32,
    #[prost(uint32, optional, tag = "5")]
    pub sampling_rate: Option<u32>,
    #[prost(int64, optional, tag = "6")]
    pub time_flow_start_ns: Option<i64>,
    #[prost(int64, optional, tag = "7")]
    pub time_flow_end_ns: Option<i64>,
    #[prost(uint64, optional, tag = "8")]
    pub bytes: Option<u64>,
    #[prost(uint64, optional, tag = "9")]
    pub packets: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "10")]
    pub src_addr: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub dst_addr: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "12")]
    pub src_mac: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub dst_mac: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "14")]
    pub etype: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub proto: Option<u32>,
    #[prost(uint32, optional, tag = "16")]
    pub src_port: Option<u32>,
    #[prost(uint32, optional, tag = "17")]
    pub dst_port: Option<u32>,
    #[prost(uint32, optional, tag = "18")]
    pub in_if: Option<u32>,
    #[prost(uint32, optional, tag = "19")]
    pub out_if: Option<u32>,
    #[prost(uint32, optional, tag = "20")]
    pub ip_tos: Option<u32>,
    #[prost(uint32, optional, tag = "21")]
    pub ip_ttl: Option<u32>,
    #[prost(uint32, optional, tag = "22")]
    pub tcp_flags: Option<u32>,
    #[prost(uint32, optional, tag = "23")]
    pub icmp_type: Option<u32>,
    #[prost(uint32, optional, tag = "24")]
    pub icmp_code: Option<u32>,
    #[prost(uint32, optional, tag = "25")]
    pub ipv6_flow_label: Option<u32>,
    #[prost(uint32, optional, tag = "26")]
    pub fragment_id: Option<u32>,
    #[prost(uint32, optional, tag = "27")]
    pub fragment_offset: Option<u32>,
    #[prost(uint32, optional, tag = "28")]
    pub src_as: Option<u32>,
    #[prost(uint32, optional, tag = "29")]
    pub dst_as: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "30")]
    pub next_hop: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "31")]
    pub src_net: Option<u32>,
    #[prost(uint32, optional, tag = "32")]
    pub dst_net: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "33")]
    pub bgp_next_hop: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "34")]
    pub src_vlan: Option<u32>,
    #[prost(uint32, optional, tag = "35")]
    pub dst_vlan: Option<u32>,
    #[prost(uint32, optional, tag = "36")]
    pub observation_domain_id: Option<u32>,
    #[prost(uint32, optional, tag = "37")]
    pub forwarding_status: Option<u32>,
}

/// An address on the wire: 4 bytes for IPv4, 16 for IPv6.
fn ip_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The `CommonFlow` fields that [`FlowMessage::from_flow`] maps: a field
/// added to the core fails this check until it is mapped there.
const MAPPED_FIELDS: usize = 37;
const _: () = assert!(CommonFlow::FIELD_NAMES.len() == MAPPED_FIELDS);

impl FlowMessage {
    pub fn from_flow(flow: &CommonFlow) -> Self {
        let CommonFlow {
            flow_type,
            time_received_ns,
            sequence_num,
            sampling_rate,
            sampler_address,
            time_flow_start_ns,
            time_flow_end_ns,
            bytes,
            packets,
            src_addr,
            dst_addr,
            src_mac,
            dst_mac,
            etype,
            proto,
            src_port,
            dst_port,
            in_if,
            out_if,
            ip_tos,
            ip_ttl,
            tcp_flags,
            icmp_type,
            icmp_code,
            ipv6_flow_label,
            fragment_id,
            fragment_offset,
            src_as,
            dst_as,
            next_hop,
            src_net,
            dst_net,
            bgp_next_hop,
            src_vlan,
            dst_vlan,
            observation_domain_id,
            forwarding_status,
            ..
        } = flow;
        Self {
            flow_type: FlowType::from(*flow_type).into(),
            time_received_ns: *time_received_ns,
            sequence_num: *sequence_num,
            sampling_rate: *sampling_rate,
            sampler_address: ip_bytes(*sampler_address),
            time_flow_start_ns: *time_flow_start_ns,
            time_flow_end_ns: *time_flow_end_ns,
            bytes: *bytes,
            packets: *packets,
            src_addr: src_addr.map(ip_bytes),
            dst_addr: dst_addr.map(ip_bytes),
            src_mac: src_mac.map(|m| m.octets().to_vec()),
            dst_mac: dst_mac.map(|m| m.octets().to_vec()),
            etype: etype.map(u32::from),
            proto: proto.map(u32::from),
            src_port: src_port.map(u32::from),
            dst_port: dst_port.map(u32::from),
            in_if: *in_if,
            out_if: *out_if,
            ip_tos: ip_tos.map(u32::from),
            ip_ttl: ip_ttl.map(u32::from),
            tcp_flags: tcp_flags.map(u32::from),
            icmp_type: icmp_type.map(u32::from),
            icmp_code: icmp_code.map(u32::from),
            ipv6_flow_label: *ipv6_flow_label,
            fragment_id: *fragment_id,
            fragment_offset: fragment_offset.map(u32::from),
            src_as: *src_as,
            dst_as: *dst_as,
            next_hop: next_hop.map(ip_bytes),
            src_net: src_net.map(u32::from),
            dst_net: dst_net.map(u32::from),
            bgp_next_hop: bgp_next_hop.map(ip_bytes),
            src_vlan: src_vlan.map(u32::from),
            dst_vlan: dst_vlan.map(u32::from),
            observation_domain_id: *observation_domain_id,
            forwarding_status: *forwarding_status,
        }
    }
}

/// Appends `value` as the protobuf field `number`, in the wire form of
/// its kind's type in `rustflow.proto`.
fn encode_added(buf: &mut Vec<u8>, text: &mut Vec<u8>, number: u32, value: Scalar<'_>) {
    match value {
        Scalar::Unsigned(v) => {
            encode_key(number, WireType::Varint, buf);
            encode_varint(v, buf);
        }
        Scalar::Signed(v) => {
            encode_key(number, WireType::Varint, buf);
            // sint64: zigzag, so that small negative numbers stay short.
            encode_varint(((v << 1) ^ (v >> 63)) as u64, buf);
        }
        Scalar::Timestamp(v) => {
            encode_key(number, WireType::Varint, buf);
            encode_varint(v as u64, buf);
        }
        Scalar::Boolean(v) => {
            encode_key(number, WireType::Varint, buf);
            encode_varint(v.into(), buf);
        }
        Scalar::Float(v) => {
            encode_key(number, WireType::SixtyFourBit, buf);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        Scalar::String(_) | Scalar::Address(_) | Scalar::Mac(_) | Scalar::Octets(_) => {
            text.clear();
            value.write_text(text);
            encode_key(number, WireType::LengthDelimited, buf);
            encode_varint(text.len() as u64, buf);
            buf.extend_from_slice(text);
        }
    }
}

/// Length-delimited protobuf, one [`FlowMessage`] per record, followed in
/// the same message by the added fields, each under its own number.
pub struct Protobuf {
    out: BufWriter<Writer>,
    added: Vec<Added>,
    /// One message, written in a single call.
    buf: Vec<u8>,
    text: Vec<u8>,
    length: Vec<u8>,
}

impl Protobuf {
    pub fn open(out: Writer, schema: &Schema) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            added: schema.added().map(|(_, added)| added).collect(),
            buf: Vec::with_capacity(512),
            text: Vec::new(),
            length: Vec::with_capacity(4),
        })
    }
}

impl Encoder for Protobuf {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.buf.clear();
        FlowMessage::from_flow(flow)
            .encode(&mut self.buf)
            .map_err(io::Error::other)?;
        for added in &self.added {
            if let Some(value) = added.value(flow, enriched) {
                encode_added(&mut self.buf, &mut self.text, added.number, value);
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

    use rustflow_core::common_flow::FlowType as CoreFlowType;
    use rustflow_core::value::Value;

    use super::*;
    use crate::field::{self, Field, Kind};

    /// The added fields of the test, as a consumer would declare them.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct Consumer {
        #[prost(uint32, tag = "4")]
        sequence_num: u32,
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
        #[prost(string, optional, tag = "1004")]
        host: Option<String>,
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
                field("count", Kind::Unsigned, None),
                field("delta", Kind::Signed, None),
                field("ratio", Kind::Float, None),
                field("ok", Kind::Boolean, None),
                field("start", Kind::Timestamp, Some(2000)),
                field("host", Kind::Text, None),
                field("missing", Kind::Text, None),
            ],
            &[field("site", Kind::Text, None)],
        )
        .unwrap();
        let memory = Memory::default();
        let mut protobuf = Protobuf::open(Box::new(memory.clone()), &schema).unwrap();
        let mut flow = CommonFlow::new(CoreFlowType::Ipfix, 0, [192, 0, 2, 1].into(), 9);
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
                sequence_num: 9,
                count: Some(7),
                delta: Some(-3),
                ratio: Some(0.5),
                ok: Some(true),
                start: Some(2_000_000_000),
                host: Some("192.0.2.7".into()),
                missing: None,
                site: Some("lab".into()),
            }
        );
    }
}
