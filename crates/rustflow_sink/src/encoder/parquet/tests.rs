use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

use arrow_array::{Array, StringArray, UInt16Array, UInt32Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use super::*;

fn read_all(path: &std::path::Path) -> (usize, Vec<RecordBatch>) {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap();
    let row_groups = builder.metadata().num_row_groups();
    let batches: Vec<RecordBatch> = builder.build().unwrap().map(|b| b.unwrap()).collect();
    (row_groups, batches)
}

#[test]
fn writes_addresses_as_text() {
    let path = std::env::temp_dir().join("rustflow_sink_parquet_test.parquet");
    let mut flow = CommonFlow::new(FlowType::Ipfix);
    flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    flow.dst_addr = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    flow.src_mac = Some(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
    flow.src_port = Some(443);
    flow.time_received_ns = Some(1_704_207_600_000_000_000);

    let empty = CommonFlow::new(FlowType::SflowV5);

    let enriched_fields = vec!["src_asn".to_string()];
    let mut encoder =
        Parquet::open(Box::new(File::create(&path).unwrap()), &enriched_fields).unwrap();

    let mut enriched = Enriched::new(1);
    enriched.set(0, "13335");
    encoder.encode(&flow, &enriched).unwrap();
    encoder.encode(&empty, &Enriched::new(1)).unwrap();
    encoder.finish().unwrap();

    let (row_groups, batches) = read_all(&path);
    assert_eq!(row_groups, 1);
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(batch.num_columns(), 37 + 1);

    let column = |name: &str| batch.column(batch.schema().index_of(name).unwrap()).clone();
    let text = |name: &str| {
        let col = column(name);
        col.as_any().downcast_ref::<StringArray>().unwrap().clone()
    };

    let flow_type = text("flow_type");
    assert_eq!(flow_type.value(0), "IPFIX");
    assert_eq!(flow_type.value(1), "SFLOW_V5");

    let src_addr = text("src_addr");
    assert_eq!(src_addr.value(0), "10.0.0.1");
    assert!(src_addr.is_null(1));

    assert_eq!(text("dst_addr").value(0), Ipv6Addr::LOCALHOST.to_string());

    let src_mac = text("src_mac");
    assert_eq!(src_mac.value(0), "00:11:22:33:44:55");
    assert!(src_mac.is_null(1));

    let bgp = text("bgp_next_hop");
    assert!(bgp.is_null(0) && bgp.is_null(1));

    let src_port = column("src_port");
    let src_port = src_port.as_any().downcast_ref::<UInt16Array>().unwrap();
    assert_eq!(src_port.value(0), 443);

    let src_asn = text("src_asn");
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

/// A small batch size: rows spanning several batches come back once, in
/// order, with their enrichment values.
#[test]
fn rows_keep_their_order_across_batches() {
    let path = std::env::temp_dir().join("rustflow_sink_parquet_batches.parquet");
    let fields = vec!["src_asn".to_string()];
    let mut encoder =
        Parquet::open_with_batch_rows(Box::new(File::create(&path).unwrap()), &fields, 8).unwrap();

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

    let (_, batches) = read_all(&path);
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 50);

    let mut seen: Vec<u32> = Vec::new();
    let mut asns: Vec<Option<String>> = Vec::new();
    for batch in &batches {
        let seq = batch
            .column(batch.schema().index_of("sequence_num").unwrap())
            .clone();
        seen.extend(
            seq.as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap()
                .values()
                .iter()
                .copied(),
        );
        let asn = batch
            .column(batch.schema().index_of("src_asn").unwrap())
            .clone();
        let asn = asn.as_any().downcast_ref::<StringArray>().unwrap();
        asns.extend((0..asn.len()).map(|i| asn.is_valid(i).then(|| asn.value(i).to_string())));
    }
    assert_eq!(seen, (0..50).collect::<Vec<u32>>());
    assert_eq!(asns[0].as_deref(), Some("as0"));
    assert_eq!(asns[1], None);
    assert_eq!(asns[48].as_deref(), Some("as48"));

    std::fs::remove_file(&path).ok();
}
