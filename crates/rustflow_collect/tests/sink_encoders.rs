//! Every encoder against the `FlowEncoder` trait.
mod common;

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arrow_array::{Array, RecordBatch, StringArray, UInt16Array, UInt32Array};
use arrow_schema::{DataType, TimeUnit};
use common::{SharedBuf, sample_flow};
use macaddr::MacAddr6;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use prost::Message;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};
use rustflow_sink::encoder::FlowMessage;
use rustflow_sink::*;

const FLOW_COLUMNS: usize = 37;

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn encode<E: FlowEncoder>(names: &[String], flows: &[(CommonFlow, Enriched)]) -> Vec<u8> {
    let buf = SharedBuf::default();
    let mut encoder = E::open(buf.boxed(), names).unwrap();
    for (flow, enriched) in flows {
        encoder.encode(flow, enriched).unwrap();
    }
    encoder.finish().unwrap();
    buf.contents()
}

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
    f.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)));
    f.bgp_next_hop = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    f.template_id = Some(256);
    f
}

// ---------------------------------------------------------------------------
// Enriched

#[test]
fn enriched_clear_resets_every_slot_but_keeps_the_width() {
    let mut e = Enriched::new(2);
    e.set(1, "13335");
    assert_eq!(e.get(0), None);
    assert_eq!(e.get(1), Some("13335"));

    e.clear();
    assert_eq!(e.iter().len(), 2);
    assert!(e.iter().all(|v| v.is_none()));
}

// ---------------------------------------------------------------------------
// CSV

fn csv_rows(names: &[String], flows: &[(CommonFlow, Enriched)]) -> Vec<Vec<String>> {
    let bytes = encode::<Csv>(names, flows);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(bytes.as_slice());
    reader
        .records()
        .map(|r| r.unwrap().iter().map(str::to_string).collect())
        .collect()
}

#[test]
fn csv_record_matches_the_header_width() {
    let mut enriched = Enriched::new(2);
    enriched.set(0, "13335");
    let rows = csv_rows(
        &names(&["src_asn", "src_org"]),
        &[(sample_flow(), enriched)],
    );

    let header = &rows[0];
    let row = &rows[1];
    assert_eq!(header.len(), FLOW_COLUMNS + 2);
    assert_eq!(header[0], "flow_type");
    assert_eq!(header[9], "src_addr");
    assert_eq!(header[36], "template_id");
    assert_eq!(header[FLOW_COLUMNS], "src_asn");
    assert_eq!(header[FLOW_COLUMNS + 1], "src_org");

    assert_eq!(row.len(), header.len());
    assert_eq!(row[0], "IPFIX");
    assert_eq!(row[7], "1234");
    assert_eq!(row[10], "");
    assert_eq!(row[FLOW_COLUMNS], "13335");
    assert_eq!(row[FLOW_COLUMNS + 1], "");
}

#[test]
fn csv_values_do_not_leak_between_flows() {
    let mut second = sample_flow();
    second.src_addr = None;
    second.bytes = 7;
    let rows = csv_rows(
        &[],
        &[
            (sample_flow(), Enriched::new(0)),
            (second, Enriched::new(0)),
        ],
    );
    assert_eq!(rows[1][9], "10.1.2.3");
    assert_eq!(rows[2][9], "");
    assert_eq!(rows[2][7], "7");
}

// ---------------------------------------------------------------------------
// NDJSON

fn ndjson_line(names: &[String], enriched: &Enriched) -> String {
    String::from_utf8(encode::<Ndjson>(
        names,
        &[(sample_flow(), enriched.clone())],
    ))
    .unwrap()
}

#[test]
fn ndjson_line_is_valid_json_with_the_extra_keys() {
    let mut enriched = Enriched::new(2);
    enriched.set(0, "13335");
    enriched.set(1, "Cloud \"Net\", Inc.\\x");

    let line = ndjson_line(&names(&["src_asn", "src_org"]), &enriched);

    assert!(line.ends_with('\n'));
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["src_asn"], "13335");
    assert_eq!(value["src_org"], "Cloud \"Net\", Inc.\\x");
    assert_eq!(value["src_port"], 443);
    assert_eq!(value["flow_type"], "IPFIX");
}

#[test]
fn ndjson_omits_absent_fields() {
    let line = ndjson_line(&names(&["src_asn"]), &Enriched::new(1));
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(value.get("src_asn").is_none());
    assert!(value.get("dst_addr").is_none());
}

#[test]
fn ndjson_row_without_enrichment_is_the_plain_struct() {
    let plain = serde_json::to_string(&sample_flow()).unwrap() + "\n";
    assert_eq!(ndjson_line(&names(&["src_asn"]), &Enriched::new(1)), plain);
}

#[test]
fn ndjson_raw_values_are_one_document_per_line() {
    let buf = SharedBuf::default();
    let mut encoder = Ndjson::open(buf.boxed(), &[]).unwrap();
    encoder.write_value(&serde_json::json!({"a": 1})).unwrap();
    encoder.write_value(&[1, 2, 3]).unwrap();
    encoder.finish().unwrap();
    assert_eq!(buf.text(), "{\"a\":1}\n[1,2,3]\n");
}

// ---------------------------------------------------------------------------
// Protobuf

#[test]
fn protobuf_messages_round_trip_through_prost() {
    let names = names(&["src_asn", "src_org", "dst_country"]);
    let mut enriched = Enriched::new(3);
    enriched.set(0, "13335");
    enriched.set(1, "Cloudflare, Inc.");

    for flow in [CommonFlow::new(FlowType::Ipfix), sample_flow(), full_flow()] {
        let bytes = encode::<Protobuf>(&names, &[(flow.clone(), enriched.clone())]);
        let decoded = FlowMessage::decode_length_delimited(bytes.as_slice()).unwrap();
        assert_eq!(decoded, FlowMessage::from_flow(&flow, &names, &enriched));
        assert_eq!(decoded.enriched.len(), 2);
        assert_eq!(decoded.flow_type, flow.flow_type.to_string());
    }
}

#[test]
fn protobuf_addresses_are_raw_octets_and_some_zero_is_kept() {
    let bytes = encode::<Protobuf>(&[], &[(full_flow(), Enriched::new(0))]);
    let decoded = FlowMessage::decode_length_delimited(bytes.as_slice()).unwrap();
    assert_eq!(decoded.src_addr.as_deref(), Some(&[10, 1, 2, 3][..]));
    assert_eq!(decoded.dst_addr.as_ref().map(Vec::len), Some(16));
    assert_eq!(
        decoded.src_mac.as_deref(),
        Some(&[0, 0x11, 0x22, 0x33, 0x44, 0x55][..])
    );
    assert_eq!(decoded.proto, Some(0));
    assert_eq!(decoded.out_if, Some(0));
    assert_eq!(decoded.icmp_type, None);
}

/// Field 1 is the flow type, 37 the last flow field, 38 the map.
#[test]
fn protobuf_wire_tags_follow_the_published_contract() {
    let mut flow = CommonFlow::new(FlowType::Ipfix);
    flow.template_id = Some(1);
    let mut enriched = Enriched::new(1);
    enriched.set(0, "v");
    let bytes = encode::<Protobuf>(&names(&["k"]), &[(flow, enriched)]);
    let body = &bytes[1..];
    assert_eq!(&body[..7], b"\x0a\x05IPFIX");
    assert_eq!(&body[7..10], [0xa8, 0x02, 0x01]);
    assert_eq!(&body[10..12], [0xb2, 0x02]);
}

#[test]
fn protobuf_output_is_framed_per_message() {
    let two = encode::<Protobuf>(
        &[],
        &[
            (sample_flow(), Enriched::new(0)),
            (sample_flow(), Enriched::new(0)),
        ],
    );
    let body_len = two[0] as usize;
    assert_eq!(two.len(), 2 * (body_len + 1));
    assert_eq!(two[body_len + 1] as usize, body_len);

    let mut enriched = Enriched::new(1);
    enriched.set(0, "x".repeat(300).as_str());
    let long = encode::<Protobuf>(&names(&["big"]), &[(sample_flow(), enriched)]);
    assert!(long[0] & 0x80 != 0, "multi-byte length prefix");
    assert!(FlowMessage::decode_length_delimited(long.as_slice()).is_ok());
}

// ---------------------------------------------------------------------------
// Parquet

fn read_parquet(path: &std::path::Path) -> (usize, Vec<RecordBatch>) {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap();
    let row_groups = builder.metadata().num_row_groups();
    let batches = builder.build().unwrap().map(|b| b.unwrap()).collect();
    (row_groups, batches)
}

fn text_column(batch: &RecordBatch, name: &str) -> StringArray {
    let column = batch.column(batch.schema().index_of(name).unwrap());
    column
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .clone()
}

#[test]
fn parquet_writes_addresses_as_text() {
    let path = std::env::temp_dir().join("rustflow_sink_parquet_test.parquet");
    let mut flow = CommonFlow::new(FlowType::Ipfix);
    flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    flow.dst_addr = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    flow.src_mac = Some(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
    flow.src_port = Some(443);
    flow.time_received_ns = Some(1_704_207_600_000_000_000);
    let empty = CommonFlow::new(FlowType::SflowV5);

    let mut encoder =
        Parquet::open(Box::new(File::create(&path).unwrap()), &names(&["src_asn"])).unwrap();
    let mut enriched = Enriched::new(1);
    enriched.set(0, "13335");
    encoder.encode(&flow, &enriched).unwrap();
    encoder.encode(&empty, &Enriched::new(1)).unwrap();
    encoder.finish().unwrap();

    let (row_groups, batches) = read_parquet(&path);
    assert_eq!(row_groups, 1);
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(batch.num_columns(), FLOW_COLUMNS + 1);

    let flow_type = text_column(batch, "flow_type");
    assert_eq!(flow_type.value(0), "IPFIX");
    assert_eq!(flow_type.value(1), "SFLOW_V5");

    let src_addr = text_column(batch, "src_addr");
    assert_eq!(src_addr.value(0), "10.0.0.1");
    assert!(src_addr.is_null(1));
    assert_eq!(
        text_column(batch, "dst_addr").value(0),
        Ipv6Addr::LOCALHOST.to_string()
    );

    let src_mac = text_column(batch, "src_mac");
    assert_eq!(src_mac.value(0), "00:11:22:33:44:55");
    assert!(src_mac.is_null(1));

    let bgp = text_column(batch, "bgp_next_hop");
    assert!(bgp.is_null(0) && bgp.is_null(1));

    let src_port = batch.column(batch.schema().index_of("src_port").unwrap());
    let src_port = src_port.as_any().downcast_ref::<UInt16Array>().unwrap();
    assert_eq!(src_port.value(0), 443);

    let src_asn = text_column(batch, "src_asn");
    assert_eq!(src_asn.value(0), "13335");
    assert!(src_asn.is_null(1));

    let schema = batch.schema();
    assert!(!schema.field_with_name("bytes").unwrap().is_nullable());
    assert!(schema.field_with_name("src_port").unwrap().is_nullable());
    assert_eq!(
        schema
            .field_with_name("time_received_ns")
            .unwrap()
            .data_type(),
        &DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn parquet_rows_keep_their_order_across_batches() {
    let path = std::env::temp_dir().join("rustflow_sink_parquet_batches.parquet");
    let mut encoder = Parquet::open_with_batch_rows(
        Box::new(File::create(&path).unwrap()),
        &names(&["src_asn"]),
        8,
    )
    .unwrap();

    let mut enriched = Enriched::new(1);
    for i in 0..50u32 {
        let mut flow = CommonFlow::new(FlowType::NetflowV9);
        flow.sequence_num = i;
        flow.time_received_ns = Some(1_704_207_600_000_000_000 + i64::from(i) * 1_000);
        flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 7) as u8)));
        enriched.clear();
        if i % 2 == 0 {
            enriched.set(0, format!("as{i}"));
        }
        encoder.encode(&flow, &enriched).unwrap();
    }
    encoder.finish().unwrap();

    let (_, batches) = read_parquet(&path);
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 50);

    let mut seen: Vec<u32> = Vec::new();
    let mut asns: Vec<Option<String>> = Vec::new();
    for batch in &batches {
        let seq = batch.column(batch.schema().index_of("sequence_num").unwrap());
        seen.extend(
            seq.as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap()
                .values()
                .iter()
                .copied(),
        );
        let asn = text_column(batch, "src_asn");
        asns.extend((0..asn.len()).map(|i| asn.is_valid(i).then(|| asn.value(i).to_string())));
    }
    assert_eq!(seen, (0..50).collect::<Vec<u32>>());
    assert_eq!(asns[0].as_deref(), Some("as0"));
    assert_eq!(asns[1], None);
    assert_eq!(asns[48].as_deref(), Some("as48"));

    std::fs::remove_file(&path).ok();
}
