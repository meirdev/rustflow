use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

use arrow_array::builder::{FixedSizeBinaryBuilder, StringBuilder};
use arrow_array::{
    ArrayRef, RecordBatch, StringArray, TimestampNanosecondArray, UInt8Array, UInt16Array,
    UInt32Array, UInt64Array,
};
use arrow_schema::{ArrowError, DataType, Field, Schema, TimeUnit};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use rustflow_core::common::common_flow::CommonFlow;

/// Number of buffered flows before a row group batch is handed to the writer.
const BATCH_ROWS: usize = 8192;

/// Width of an IP address column: IPv4 addresses are stored as IPv4-mapped
/// IPv6 so both families share one fixed-size column.
const IP_ADDR_LEN: i32 = 16;

/// Width of a MAC address column.
const MAC_ADDR_LEN: i32 = 6;

type Row = (CommonFlow, Vec<Option<String>>);

/// Writes common flows to a Snappy-compressed Parquet file.
///
/// Flows are buffered and converted to Arrow record batches of [`BATCH_ROWS`]
/// rows; the Parquet footer is only written by [`ParquetSink::finish`], so the
/// sink must be finished before the file is usable.
pub struct ParquetSink {
    writer: Option<ArrowWriter<Box<dyn Write + Send>>>,
    schema: Arc<Schema>,
    enriched_fields: Vec<String>,
    rows: Vec<Row>,
}

impl ParquetSink {
    pub fn new(
        output: Box<dyn Write + Send>,
        enriched_fields: &[String],
    ) -> Result<Self, ParquetError> {
        let schema = Arc::new(build_schema(enriched_fields));
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();
        let writer = ArrowWriter::try_new(output, Arc::clone(&schema), Some(props))?;

        Ok(Self {
            writer: Some(writer),
            schema,
            enriched_fields: enriched_fields.to_vec(),
            rows: Vec::with_capacity(BATCH_ROWS),
        })
    }

    pub fn write(
        &mut self,
        flow: &CommonFlow,
        enriched: &std::collections::HashMap<String, String>,
    ) -> Result<(), ParquetError> {
        let values = self
            .enriched_fields
            .iter()
            .map(|field| enriched.get(field).cloned())
            .collect();
        self.rows.push((flow.clone(), values));

        if self.rows.len() >= BATCH_ROWS {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Flush the buffered rows and write the Parquet footer.
    pub fn finish(&mut self) -> Result<(), ParquetError> {
        self.flush_batch()?;
        if let Some(writer) = self.writer.take() {
            writer.close()?;
        }
        Ok(())
    }

    fn flush_batch(&mut self) -> Result<(), ParquetError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let batch = self.build_batch()?;
        self.rows.clear();
        if let Some(writer) = self.writer.as_mut() {
            writer.write(&batch)?;
        }
        Ok(())
    }

    fn build_batch(&self) -> Result<RecordBatch, ArrowError> {
        let rows = &self.rows;

        // Column expression over the flow of each buffered row.
        macro_rules! prim {
            ($ty:ty, $field:ident) => {
                Arc::new(<$ty>::from(
                    rows.iter().map(|(f, _)| f.$field).collect::<Vec<_>>(),
                )) as ArrayRef
            };
        }

        // IP address column, stored as 16 fixed bytes.
        macro_rules! ip {
            ($field:ident) => {
                fixed_binary(
                    IP_ADDR_LEN,
                    rows.iter().map(|(f, _)| f.$field.map(ip_octets)),
                )?
            };
        }

        // MAC address column, stored as 6 fixed bytes.
        macro_rules! mac {
            ($field:ident) => {
                fixed_binary(
                    MAC_ADDR_LEN,
                    rows.iter().map(|(f, _)| f.$field.map(|m| m.into_array())),
                )?
            };
        }

        macro_rules! timestamp {
            ($field:ident) => {
                Arc::new(
                    TimestampNanosecondArray::from(
                        rows.iter().map(|(f, _)| f.$field).collect::<Vec<_>>(),
                    )
                    .with_timezone("UTC"),
                ) as ArrayRef
            };
        }

        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|(f, _)| f.flow_type.to_string()),
            )) as ArrayRef,
            timestamp!(time_received_ns),
            prim!(UInt32Array, sequence_num),
            prim!(UInt32Array, sampling_rate),
            ip!(sampler_address),
            timestamp!(time_flow_start_ns),
            timestamp!(time_flow_end_ns),
            prim!(UInt64Array, bytes),
            prim!(UInt64Array, packets),
            ip!(src_addr),
            ip!(dst_addr),
            mac!(src_mac),
            mac!(dst_mac),
            prim!(UInt16Array, etype),
            prim!(UInt8Array, proto),
            prim!(UInt16Array, src_port),
            prim!(UInt16Array, dst_port),
            prim!(UInt32Array, in_if),
            prim!(UInt32Array, out_if),
            prim!(UInt8Array, ip_tos),
            prim!(UInt8Array, ip_ttl),
            prim!(UInt8Array, tcp_flags),
            prim!(UInt8Array, icmp_type),
            prim!(UInt8Array, icmp_code),
            prim!(UInt32Array, ipv6_flow_label),
            prim!(UInt32Array, fragment_id),
            prim!(UInt16Array, fragment_offset),
            prim!(UInt32Array, src_as),
            prim!(UInt32Array, dst_as),
            ip!(next_hop),
            prim!(UInt8Array, src_net),
            prim!(UInt8Array, dst_net),
            ip!(bgp_next_hop),
            prim!(UInt16Array, src_vlan),
            prim!(UInt16Array, dst_vlan),
            prim!(UInt32Array, observation_domain_id),
            prim!(UInt16Array, template_id),
        ];

        for index in 0..self.enriched_fields.len() {
            let mut builder = StringBuilder::with_capacity(rows.len(), rows.len() * 8);
            for (_, values) in rows {
                builder.append_option(values[index].as_deref());
            }
            columns.push(Arc::new(builder.finish()) as ArrayRef);
        }

        RecordBatch::try_new(Arc::clone(&self.schema), columns)
    }
}

impl Drop for ParquetSink {
    fn drop(&mut self) {
        if let Err(err) = self.finish() {
            eprintln!("Failed to finalize parquet file: {}", err);
        }
    }
}

/// Fixed-width byte representation of an address: IPv4 is widened to its
/// IPv4-mapped IPv6 form so every address occupies 16 bytes.
fn ip_octets(addr: IpAddr) -> [u8; IP_ADDR_LEN as usize] {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn fixed_binary<const N: usize>(
    width: i32,
    values: impl ExactSizeIterator<Item = Option<[u8; N]>>,
) -> Result<ArrayRef, ArrowError> {
    let mut builder = FixedSizeBinaryBuilder::with_capacity(values.len(), width);
    for value in values {
        match value {
            Some(bytes) => builder.append_value(bytes)?,
            None => builder.append_null(),
        }
    }
    Ok(Arc::new(builder.finish()) as ArrayRef)
}

fn build_schema(enriched_fields: &[String]) -> Schema {
    let timestamp = || DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));

    let mut fields = vec![
        Field::new("flow_type", DataType::Utf8, false),
        Field::new("time_received_ns", timestamp(), true),
        Field::new("sequence_num", DataType::UInt32, false),
        Field::new("sampling_rate", DataType::UInt32, true),
        Field::new(
            "sampler_address",
            DataType::FixedSizeBinary(IP_ADDR_LEN),
            true,
        ),
        Field::new("time_flow_start_ns", timestamp(), true),
        Field::new("time_flow_end_ns", timestamp(), true),
        Field::new("bytes", DataType::UInt64, false),
        Field::new("packets", DataType::UInt64, false),
        Field::new("src_addr", DataType::FixedSizeBinary(IP_ADDR_LEN), true),
        Field::new("dst_addr", DataType::FixedSizeBinary(IP_ADDR_LEN), true),
        Field::new("src_mac", DataType::FixedSizeBinary(MAC_ADDR_LEN), true),
        Field::new("dst_mac", DataType::FixedSizeBinary(MAC_ADDR_LEN), true),
        Field::new("etype", DataType::UInt16, true),
        Field::new("proto", DataType::UInt8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("in_if", DataType::UInt32, true),
        Field::new("out_if", DataType::UInt32, true),
        Field::new("ip_tos", DataType::UInt8, true),
        Field::new("ip_ttl", DataType::UInt8, true),
        Field::new("tcp_flags", DataType::UInt8, true),
        Field::new("icmp_type", DataType::UInt8, true),
        Field::new("icmp_code", DataType::UInt8, true),
        Field::new("ipv6_flow_label", DataType::UInt32, true),
        Field::new("fragment_id", DataType::UInt32, true),
        Field::new("fragment_offset", DataType::UInt16, true),
        Field::new("src_as", DataType::UInt32, true),
        Field::new("dst_as", DataType::UInt32, true),
        Field::new("next_hop", DataType::FixedSizeBinary(IP_ADDR_LEN), true),
        Field::new("src_net", DataType::UInt8, true),
        Field::new("dst_net", DataType::UInt8, true),
        Field::new("bgp_next_hop", DataType::FixedSizeBinary(IP_ADDR_LEN), true),
        Field::new("src_vlan", DataType::UInt16, true),
        Field::new("dst_vlan", DataType::UInt16, true),
        Field::new("observation_domain_id", DataType::UInt32, true),
        Field::new("template_id", DataType::UInt16, true),
    ];

    for field in enriched_fields {
        fields.push(Field::new(field, DataType::Utf8, true));
    }

    Schema::new(fields)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use arrow_array::{Array, FixedSizeBinaryArray, StringArray, UInt16Array};
    use macaddr::MacAddr6;
    use rustflow_core::common::common_flow::FlowType;

    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn writes_addresses_as_fixed_binary() {
        let path = temp_path("rustflow_parquet_sink_test.parquet");
        let mut flow = CommonFlow::new(FlowType::Ipfix);
        flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        flow.dst_addr = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        flow.src_mac = Some(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
        flow.src_port = Some(443);
        flow.time_received_ns = Some(1_704_207_600_000_000_000);

        let empty = CommonFlow::new(FlowType::SflowV5);

        let enriched_fields = vec!["src_asn".to_string()];
        let mut sink =
            ParquetSink::new(Box::new(File::create(&path).unwrap()), &enriched_fields).unwrap();

        let mut enriched = HashMap::new();
        enriched.insert("src_asn".to_string(), "13335".to_string());
        sink.write(&flow, &enriched).unwrap();
        sink.write(&empty, &HashMap::new()).unwrap();
        sink.finish().unwrap();

        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            File::open(&path).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        let batches: Vec<_> = reader.map(|b| b.unwrap()).collect();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.num_rows(), 2);

        let column = |name: &str| batch.column(batch.schema().index_of(name).unwrap()).clone();

        let src_addr = column("src_addr");
        let src_addr = src_addr
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(src_addr.value_length(), IP_ADDR_LEN);
        // IPv4 is stored as its IPv4-mapped IPv6 form.
        assert_eq!(
            src_addr.value(0),
            Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets()
        );
        assert!(src_addr.is_null(1));

        let dst_addr = column("dst_addr");
        let dst_addr = dst_addr
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(dst_addr.value(0), Ipv6Addr::LOCALHOST.octets());

        let src_mac = column("src_mac");
        let src_mac = src_mac
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(src_mac.value_length(), MAC_ADDR_LEN);
        assert_eq!(src_mac.value(0), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(src_mac.is_null(1));

        let src_port = column("src_port");
        assert_eq!(
            src_port
                .as_any()
                .downcast_ref::<UInt16Array>()
                .unwrap()
                .value(0),
            443
        );

        let src_asn = column("src_asn");
        let src_asn = src_asn.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(src_asn.value(0), "13335");
        assert!(src_asn.is_null(1));

        std::fs::remove_file(&path).ok();
    }
}
