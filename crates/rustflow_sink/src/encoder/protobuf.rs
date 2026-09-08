use std::io::{self, BufWriter, Write};
use std::net::IpAddr;

use prost::encoding::{WireType, encode_key, encode_varint, encoded_len_varint, key_len};
use rustflow_core::common::common_flow::CommonFlow;

use super::text::flow_type_name;
use super::{FlowEncoder, Output, WRITE_BUFFER_BYTES};
use crate::flow::Enriched;
use crate::flow::fields::for_each_flow_field;

/// Length-delimited protobuf, one `rustflow.CommonFlow` message per record,
/// wire-compatible with `proto/rustflow.proto`.
///
/// The message is encoded by hand straight into a reused buffer: no
/// intermediate struct, no per-flow allocation. Two rules keep the bytes
/// identical to what a prost-derived message would produce:
///
/// 1. Non-optional proto3 scalars (`sequence_num`, `bytes`, `packets`) are
///    omitted when they hold the default `0`. Optional fields are emitted
///    whenever `Some`, including `Some(0)`.
/// 2. Map entries are emitted in enrichment-field order. prost iterates a
///    `HashMap`, so its order is arbitrary; decoded messages are equal.
///
/// The prost-derived `FlowMessage` in the tests is the oracle for both.
pub struct Protobuf {
    out: BufWriter<Output>,
    names: Vec<String>,
    /// One message body, reused.
    body: Vec<u8>,
}

fn put_varint(tag: u32, value: u64, buf: &mut Vec<u8>) {
    encode_key(tag, WireType::Varint, buf);
    encode_varint(value, buf);
}

/// An optional scalar: present whenever `Some`.
fn put_opt(tag: u32, value: Option<impl Into<u64>>, buf: &mut Vec<u8>) {
    if let Some(v) = value {
        put_varint(tag, v.into(), buf);
    }
}

/// An optional `int64`: two's complement as a varint, like prost.
fn put_opt_i64(tag: u32, value: Option<i64>, buf: &mut Vec<u8>) {
    if let Some(v) = value {
        put_varint(tag, v as u64, buf);
    }
}

/// A non-optional proto3 scalar: absent on the wire when it is the default.
fn put_nondefault(tag: u32, value: u64, buf: &mut Vec<u8>) {
    if value != 0 {
        put_varint(tag, value, buf);
    }
}

fn put_bytes(tag: u32, bytes: &[u8], buf: &mut Vec<u8>) {
    encode_key(tag, WireType::LengthDelimited, buf);
    encode_varint(bytes.len() as u64, buf);
    buf.extend_from_slice(bytes);
}

/// An address on the wire: 4 bytes for IPv4, 16 for IPv6.
fn put_opt_ip(tag: u32, value: Option<IpAddr>, buf: &mut Vec<u8>) {
    match value {
        Some(IpAddr::V4(a)) => put_bytes(tag, &a.octets(), buf),
        Some(IpAddr::V6(a)) => put_bytes(tag, &a.octets(), buf),
        None => {}
    }
}

/// Encoded size of a length-delimited field: key, length varint, payload.
fn bytes_field_len(tag: u32, len: usize) -> usize {
    key_len(tag) + encoded_len_varint(len as u64) + len
}

/// Write `value` as a varint into a stack buffer; returns the used prefix.
fn varint_bytes(mut value: u64, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while value >= 0x80 {
        buf[i] = (value as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    buf[i] = value as u8;
    i + 1
}

/// Tag of the `enriched` map field in `rustflow.proto`.
const ENRICHED_TAG: u32 = 38;

/// Wire tag of the flow field at 1-based `position` in the shared list.
/// The first 37 fields took tags 1..=37 and the map took 38 before the
/// list existed, so later fields skip over the map's tag.
fn wire_tag(position: u32) -> u32 {
    if position < ENRICHED_TAG {
        position
    } else {
        position + 1
    }
}

/// How each kind and presence in the shared field list goes on the wire.
/// Non-optional scalars are skipped at their default, like prost.
macro_rules! put_field {
    ($tag:expr, FlowType required, $v:expr, $b:expr) => {
        put_bytes($tag, flow_type_name($v).as_bytes(), $b)
    };
    ($tag:expr, Timestamp optional, $v:expr, $b:expr) => {
        put_opt_i64($tag, $v, $b)
    };
    ($tag:expr, U8 optional, $v:expr, $b:expr) => {
        put_opt($tag, $v, $b)
    };
    ($tag:expr, U16 optional, $v:expr, $b:expr) => {
        put_opt($tag, $v, $b)
    };
    ($tag:expr, U32 optional, $v:expr, $b:expr) => {
        put_opt($tag, $v, $b)
    };
    ($tag:expr, U32 required, $v:expr, $b:expr) => {
        put_nondefault($tag, u64::from($v), $b)
    };
    ($tag:expr, U64 required, $v:expr, $b:expr) => {
        put_nondefault($tag, $v, $b)
    };
    ($tag:expr, Ip optional, $v:expr, $b:expr) => {
        put_opt_ip($tag, $v, $b)
    };
    ($tag:expr, Mac optional, $v:expr, $b:expr) => {
        if let Some(m) = $v {
            put_bytes($tag, m.as_bytes(), $b)
        }
    };
}

/// The flow-field part of the message, expanded from the shared list:
/// one `put_field!` per column, tag from position. The destructure has no
/// `..`, so a field added to `CommonFlow` fails to compile until it is in
/// the list.
macro_rules! flow_encoder {
    ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
        fn encode_flow(flow: &CommonFlow, b: &mut Vec<u8>) {
            let CommonFlow { $( $name, )* } = flow;
            let mut position = 0;
            $(
                position += 1;
                put_field!(wire_tag(position), $kind $presence, *$name, b);
            )*
        }

        /// `(name, tag)` of every flow field, for the contract test.
        #[cfg(test)]
        fn wire_tags() -> Vec<(&'static str, u32)> {
            let mut position = 0;
            vec![ $( { position += 1; (stringify!($name), wire_tag(position)) }, )* ]
        }
    };
}
for_each_flow_field!(flow_encoder);

/// `map<string, string> enriched`: one length-delimited entry per present
/// value, holding key field 1 and value field 2. prost skips an empty
/// value inside the entry; mirror that.
fn encode_enrichment(names: &[String], enriched: &Enriched, b: &mut Vec<u8>) {
    for (name, value) in names.iter().zip(enriched.iter()) {
        let Some(value) = value else { continue };
        let value_len = if value.is_empty() {
            0
        } else {
            bytes_field_len(2, value.len())
        };
        let entry_len = bytes_field_len(1, name.len()) + value_len;
        encode_key(ENRICHED_TAG, WireType::LengthDelimited, b);
        encode_varint(entry_len as u64, b);
        put_bytes(1, name.as_bytes(), b);
        if !value.is_empty() {
            put_bytes(2, value.as_bytes(), b);
        }
    }
}

impl FlowEncoder for Protobuf {
    const EXTENSION: &'static str = "pb";

    fn open(out: Output, enriched_fields: &[String]) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            names: enriched_fields.to_vec(),
            body: Vec::with_capacity(512),
        })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.body.clear();
        encode_flow(flow, &mut self.body);
        encode_enrichment(&self.names, enriched, &mut self.body);
        let mut prefix = [0u8; 10];
        let n = varint_bytes(self.body.len() as u64, &mut prefix);
        self.out.write_all(&prefix[..n])?;
        self.out.write_all(&self.body)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// The prost-derived form of the same message. Not used by the encoder;
/// it is the oracle the tests compare the hand encoder against.
#[cfg(test)]
mod oracle {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use rustflow_core::common::common_flow::CommonFlow;

    use crate::flow::Enriched;

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FlowMessage {
        #[prost(string, tag = "1")]
        pub flow_type: String,
        #[prost(int64, optional, tag = "2")]
        pub time_received_ns: Option<i64>,
        #[prost(uint32, tag = "3")]
        pub sequence_num: u32,
        #[prost(uint32, optional, tag = "4")]
        pub sampling_rate: Option<u32>,
        #[prost(bytes = "vec", optional, tag = "5")]
        pub sampler_address: Option<Vec<u8>>,
        #[prost(int64, optional, tag = "6")]
        pub time_flow_start_ns: Option<i64>,
        #[prost(int64, optional, tag = "7")]
        pub time_flow_end_ns: Option<i64>,
        #[prost(uint64, tag = "8")]
        pub bytes: u64,
        #[prost(uint64, tag = "9")]
        pub packets: u64,
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
        pub template_id: Option<u32>,
        #[prost(map = "string, string", tag = "38")]
        pub enriched: HashMap<String, String>,
    }

    fn ip_bytes(addr: IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }

    impl FlowMessage {
        /// Today's `proto::CommonFlow::from_flow` in `rustflow_collect`.
        pub fn from_flow(flow: &CommonFlow, names: &[String], enriched: &Enriched) -> Self {
            Self {
                flow_type: flow.flow_type.to_string(),
                time_received_ns: flow.time_received_ns,
                sequence_num: flow.sequence_num,
                sampling_rate: flow.sampling_rate,
                sampler_address: flow.sampler_address.map(ip_bytes),
                time_flow_start_ns: flow.time_flow_start_ns,
                time_flow_end_ns: flow.time_flow_end_ns,
                bytes: flow.bytes,
                packets: flow.packets,
                src_addr: flow.src_addr.map(ip_bytes),
                dst_addr: flow.dst_addr.map(ip_bytes),
                src_mac: flow.src_mac.map(|m| m.into_array().to_vec()),
                dst_mac: flow.dst_mac.map(|m| m.into_array().to_vec()),
                etype: flow.etype.map(u32::from),
                proto: flow.proto.map(u32::from),
                src_port: flow.src_port.map(u32::from),
                dst_port: flow.dst_port.map(u32::from),
                in_if: flow.in_if,
                out_if: flow.out_if,
                ip_tos: flow.ip_tos.map(u32::from),
                ip_ttl: flow.ip_ttl.map(u32::from),
                tcp_flags: flow.tcp_flags.map(u32::from),
                icmp_type: flow.icmp_type.map(u32::from),
                icmp_code: flow.icmp_code.map(u32::from),
                ipv6_flow_label: flow.ipv6_flow_label,
                fragment_id: flow.fragment_id,
                fragment_offset: flow.fragment_offset.map(u32::from),
                src_as: flow.src_as,
                dst_as: flow.dst_as,
                next_hop: flow.next_hop.map(ip_bytes),
                src_net: flow.src_net.map(u32::from),
                dst_net: flow.dst_net.map(u32::from),
                bgp_next_hop: flow.bgp_next_hop.map(ip_bytes),
                src_vlan: flow.src_vlan.map(u32::from),
                dst_vlan: flow.dst_vlan.map(u32::from),
                observation_domain_id: flow.observation_domain_id,
                template_id: flow.template_id.map(u32::from),
                enriched: names
                    .iter()
                    .zip(enriched.iter())
                    .filter_map(|(name, value)| Some((name.clone(), value?.to_string())))
                    .collect(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use macaddr::MacAddr6;
    use prost::Message as _;
    use rustflow_core::common::common_flow::FlowType;

    use super::oracle::FlowMessage;
    use super::*;
    use crate::test_support::{SharedBuf, sample_flow};

    fn hand_encode(flow: &CommonFlow, names: &[&str], enriched: &Enriched) -> Vec<u8> {
        let buf = SharedBuf::default();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut encoder = Protobuf::open(buf.boxed(), &names).unwrap();
        encoder.encode(flow, enriched).unwrap();
        encoder.finish().unwrap();
        buf.contents()
    }

    fn oracle_encode(flow: &CommonFlow, names: &[&str], enriched: &Enriched) -> Vec<u8> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut out = Vec::new();
        FlowMessage::from_flow(flow, &names, enriched)
            .encode_length_delimited(&mut out)
            .unwrap();
        out
    }

    /// Every field set, including an IPv6 address and `Some(0)` optionals.
    fn full_flow() -> CommonFlow {
        let mut f = CommonFlow::new(FlowType::SflowV5);
        f.time_received_ns = Some(1_704_207_600_123_456_789);
        f.sequence_num = 4_242_424;
        f.sampling_rate = Some(1000);
        f.sampler_address = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        f.time_flow_start_ns = Some(-1);
        f.time_flow_end_ns = Some(0);
        f.bytes = 1_234_567;
        f.packets = 890;
        f.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        f.dst_addr = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        f.src_mac = Some(MacAddr6::new(0, 0x11, 0x22, 0x33, 0x44, 0x55));
        f.dst_mac = Some(MacAddr6::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        f.etype = Some(0x86dd);
        f.proto = Some(0);
        f.src_port = Some(65535);
        f.dst_port = Some(443);
        f.in_if = Some(u32::MAX);
        f.out_if = Some(0);
        f.ip_tos = Some(0x10);
        f.ip_ttl = Some(63);
        f.tcp_flags = Some(0x18);
        f.icmp_type = Some(0);
        f.icmp_code = Some(0);
        f.ipv6_flow_label = Some(0xabcde);
        f.fragment_id = Some(7);
        f.fragment_offset = Some(0);
        f.src_as = Some(64512);
        f.dst_as = Some(13335);
        f.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)));
        f.src_net = Some(24);
        f.dst_net = Some(0);
        f.bgp_next_hop = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        f.src_vlan = Some(100);
        f.dst_vlan = Some(200);
        f.observation_domain_id = Some(1);
        f.template_id = Some(256);
        f
    }

    #[test]
    fn bytes_match_prost_without_enrichment() {
        // A default flow: the non-optional zeros must be absent.
        let zero = CommonFlow::new(FlowType::Ipfix);
        assert_eq!(
            hand_encode(&zero, &[], &Enriched::new(0)),
            oracle_encode(&zero, &[], &Enriched::new(0))
        );

        assert_eq!(
            hand_encode(&full_flow(), &[], &Enriched::new(0)),
            oracle_encode(&full_flow(), &[], &Enriched::new(0))
        );
        assert_eq!(
            hand_encode(&sample_flow(), &[], &Enriched::new(0)),
            oracle_encode(&sample_flow(), &[], &Enriched::new(0))
        );
    }

    #[test]
    fn bytes_match_prost_with_one_enrichment_value() {
        // One map entry: prost's iteration order cannot differ.
        let mut enriched = Enriched::new(2);
        enriched.set(1, "Cloudflare, Inc.");
        let names = ["src_asn", "src_org"];
        assert_eq!(
            hand_encode(&full_flow(), &names, &enriched),
            oracle_encode(&full_flow(), &names, &enriched)
        );

        // An empty value is still an entry, with the value field skipped.
        let mut empty = Enriched::new(1);
        empty.set(0, "");
        assert_eq!(
            hand_encode(&sample_flow(), &["x"], &empty),
            oracle_encode(&sample_flow(), &["x"], &empty)
        );
    }

    #[test]
    fn decodes_to_the_same_message_with_several_enrichment_values() {
        let names = ["src_asn", "src_org", "dst_country"];
        let mut enriched = Enriched::new(3);
        enriched.set(0, "13335");
        enriched.set(1, "Cloudflare, Inc.");
        enriched.set(2, "US");

        let bytes = hand_encode(&full_flow(), &names, &enriched);
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let decoded = FlowMessage::decode_length_delimited(bytes.as_slice()).unwrap();
        assert_eq!(
            decoded,
            FlowMessage::from_flow(&full_flow(), &names, &enriched)
        );
        assert_eq!(decoded.enriched.len(), 3);
    }

    #[test]
    fn output_is_deterministic_and_framed_per_message() {
        let names = ["a", "b", "c"];
        let mut enriched = Enriched::new(3);
        enriched.set(0, "1");
        enriched.set(1, "2");
        enriched.set(2, "3");

        let once = hand_encode(&full_flow(), &names, &enriched);
        let again = hand_encode(&full_flow(), &names, &enriched);
        assert_eq!(once, again);

        // Two messages back to back: each starts with its own length.
        let buf = SharedBuf::default();
        let mut encoder = Protobuf::open(buf.boxed(), &[]).unwrap();
        encoder.encode(&sample_flow(), &Enriched::new(0)).unwrap();
        encoder.encode(&sample_flow(), &Enriched::new(0)).unwrap();
        encoder.finish().unwrap();
        let bytes = buf.contents();
        let body_len = bytes[0] as usize;
        assert_eq!(bytes.len(), 2 * (body_len + 1));
        assert_eq!(bytes[body_len + 1] as usize, body_len);
    }

    #[test]
    fn long_messages_get_a_multi_byte_length_prefix() {
        let long = "x".repeat(300);
        let mut enriched = Enriched::new(1);
        enriched.set(0, long.as_str());
        let bytes = hand_encode(&sample_flow(), &["big"], &enriched);
        assert_eq!(bytes, oracle_encode(&sample_flow(), &["big"], &enriched));
        assert!(
            bytes[0] & 0x80 != 0,
            "first length byte has the continuation bit"
        );
    }
    /// The wire contract as it stands: field tags are positional, the map
    /// is 38. Changing this table is a wire-format change; new fields must
    /// be appended and get tags from 39.
    #[test]
    fn wire_tags_are_the_published_contract() {
        const CONTRACT: &[(&str, u32)] = &[
            ("flow_type", 1),
            ("time_received_ns", 2),
            ("sequence_num", 3),
            ("sampling_rate", 4),
            ("sampler_address", 5),
            ("time_flow_start_ns", 6),
            ("time_flow_end_ns", 7),
            ("bytes", 8),
            ("packets", 9),
            ("src_addr", 10),
            ("dst_addr", 11),
            ("src_mac", 12),
            ("dst_mac", 13),
            ("etype", 14),
            ("proto", 15),
            ("src_port", 16),
            ("dst_port", 17),
            ("in_if", 18),
            ("out_if", 19),
            ("ip_tos", 20),
            ("ip_ttl", 21),
            ("tcp_flags", 22),
            ("icmp_type", 23),
            ("icmp_code", 24),
            ("ipv6_flow_label", 25),
            ("fragment_id", 26),
            ("fragment_offset", 27),
            ("src_as", 28),
            ("dst_as", 29),
            ("next_hop", 30),
            ("src_net", 31),
            ("dst_net", 32),
            ("bgp_next_hop", 33),
            ("src_vlan", 34),
            ("dst_vlan", 35),
            ("observation_domain_id", 36),
            ("template_id", 37),
        ];
        assert_eq!(wire_tags(), CONTRACT);
        assert_eq!(ENRICHED_TAG, 38);
        assert_eq!(
            wire_tag(38),
            39,
            "a 38th flow field must skip the map's tag"
        );
    }
}
