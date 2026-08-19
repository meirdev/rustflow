use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

use arrow_array::builder::{
    FixedSizeBinaryBuilder, StringBuilder, TimestampNanosecondBuilder, UInt8Builder,
    UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

/// Number of buffered flows before a row group batch is handed to the writer.
/// Large enough to amortize the per-batch column-writer setup across all
/// ~40 columns.
const BATCH_ROWS: usize = 32768;

/// Width of an IP address column: IPv4 addresses are stored as IPv4-mapped
/// IPv6 so both families share one fixed-size column.
const IP_ADDR_LEN: i32 = 16;

/// Width of a MAC address column.
const MAC_ADDR_LEN: i32 = 6;

/// Writes common flows to a Snappy-compressed Parquet file.
///
/// Each flow is appended field-by-field into per-column Arrow builders — no
/// per-row clone — and every [`BATCH_ROWS`] rows the builders are drained
/// into a record batch. The Parquet footer is only written by
/// [`ParquetSink::finish`], so the sink must be finished before the file is
/// usable.
pub struct ParquetSink {
    writer: Option<ArrowWriter<Box<dyn Write + Send>>>,
    schema: Arc<Schema>,
    enriched_fields: Vec<String>,
    builders: FlowBuilders,
    rows: usize,
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
            builders: FlowBuilders::new(enriched_fields.len()),
            rows: 0,
        })
    }

    pub fn write(
        &mut self,
        flow: &CommonFlow,
        enriched: &std::collections::HashMap<String, String>,
    ) -> Result<(), ParquetError> {
        let b = &mut self.builders;
        b.flow_type.append_value(match flow.flow_type {
            FlowType::NetflowV5 => "NETFLOW_V5",
            FlowType::NetflowV9 => "NETFLOW_V9",
            FlowType::Ipfix => "IPFIX",
            FlowType::SflowV5 => "SFLOW_V5",
        });
        b.time_received_ns.append_option(flow.time_received_ns);
        b.sequence_num.append_value(flow.sequence_num);
        b.sampling_rate.append_option(flow.sampling_rate);
        append_ip(&mut b.sampler_address, &flow.sampler_address)?;
        b.time_flow_start_ns.append_option(flow.time_flow_start_ns);
        b.time_flow_end_ns.append_option(flow.time_flow_end_ns);
        b.bytes.append_value(flow.bytes);
        b.packets.append_value(flow.packets);
        append_ip(&mut b.src_addr, &flow.src_addr)?;
        append_ip(&mut b.dst_addr, &flow.dst_addr)?;
        match &flow.src_mac {
            Some(m) => b.src_mac.append_value(m.into_array())?,
            None => b.src_mac.append_null(),
        }
        match &flow.dst_mac {
            Some(m) => b.dst_mac.append_value(m.into_array())?,
            None => b.dst_mac.append_null(),
        }
        b.etype.append_option(flow.etype);
        b.proto.append_option(flow.proto);
        b.src_port.append_option(flow.src_port);
        b.dst_port.append_option(flow.dst_port);
        b.in_if.append_option(flow.in_if);
        b.out_if.append_option(flow.out_if);
        b.ip_tos.append_option(flow.ip_tos);
        b.ip_ttl.append_option(flow.ip_ttl);
        b.tcp_flags.append_option(flow.tcp_flags);
        b.icmp_type.append_option(flow.icmp_type);
        b.icmp_code.append_option(flow.icmp_code);
        b.ipv6_flow_label.append_option(flow.ipv6_flow_label);
        b.fragment_id.append_option(flow.fragment_id);
        b.fragment_offset.append_option(flow.fragment_offset);
        b.src_as.append_option(flow.src_as);
        b.dst_as.append_option(flow.dst_as);
        append_ip(&mut b.next_hop, &flow.next_hop)?;
        b.src_net.append_option(flow.src_net);
        b.dst_net.append_option(flow.dst_net);
        append_ip(&mut b.bgp_next_hop, &flow.bgp_next_hop)?;
        b.src_vlan.append_option(flow.src_vlan);
        b.dst_vlan.append_option(flow.dst_vlan);
        b.observation_domain_id
            .append_option(flow.observation_domain_id);
        b.template_id.append_option(flow.template_id);
        for (builder, name) in b.enriched.iter_mut().zip(&self.enriched_fields) {
            builder.append_option(enriched.get(name));
        }

        self.rows += 1;
        if self.rows >= BATCH_ROWS {
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
        if self.rows == 0 {
            return Ok(());
        }
        let columns = self.builders.finish();
        self.rows = 0;
        let batch = RecordBatch::try_new(Arc::clone(&self.schema), columns)
            .map_err(ParquetError::from)?;
        if let Some(writer) = self.writer.as_mut() {
            writer.write(&batch)?;
        }
        Ok(())
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

fn append_ip(
    builder: &mut FixedSizeBinaryBuilder,
    value: &Option<IpAddr>,
) -> Result<(), ParquetError> {
    match value {
        Some(addr) => builder.append_value(ip_octets(*addr))?,
        None => builder.append_null(),
    }
    Ok(())
}

/// One Arrow builder per output column, in schema order.
struct FlowBuilders {
    flow_type: StringBuilder,
    time_received_ns: TimestampNanosecondBuilder,
    sequence_num: UInt32Builder,
    sampling_rate: UInt32Builder,
    sampler_address: FixedSizeBinaryBuilder,
    time_flow_start_ns: TimestampNanosecondBuilder,
    time_flow_end_ns: TimestampNanosecondBuilder,
    bytes: UInt64Builder,
    packets: UInt64Builder,
    src_addr: FixedSizeBinaryBuilder,
    dst_addr: FixedSizeBinaryBuilder,
    src_mac: FixedSizeBinaryBuilder,
    dst_mac: FixedSizeBinaryBuilder,
    etype: UInt16Builder,
    proto: UInt8Builder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    in_if: UInt32Builder,
    out_if: UInt32Builder,
    ip_tos: UInt8Builder,
    ip_ttl: UInt8Builder,
    tcp_flags: UInt8Builder,
    icmp_type: UInt8Builder,
    icmp_code: UInt8Builder,
    ipv6_flow_label: UInt32Builder,
    fragment_id: UInt32Builder,
    fragment_offset: UInt16Builder,
    src_as: UInt32Builder,
    dst_as: UInt32Builder,
    next_hop: FixedSizeBinaryBuilder,
    src_net: UInt8Builder,
    dst_net: UInt8Builder,
    bgp_next_hop: FixedSizeBinaryBuilder,
    src_vlan: UInt16Builder,
    dst_vlan: UInt16Builder,
    observation_domain_id: UInt32Builder,
    template_id: UInt16Builder,
    enriched: Vec<StringBuilder>,
}

impl FlowBuilders {
    fn new(enriched_count: usize) -> Self {
        let timestamp = || TimestampNanosecondBuilder::new().with_timezone("UTC");
        Self {
            flow_type: StringBuilder::new(),
            time_received_ns: timestamp(),
            sequence_num: UInt32Builder::new(),
            sampling_rate: UInt32Builder::new(),
            sampler_address: FixedSizeBinaryBuilder::new(IP_ADDR_LEN),
            time_flow_start_ns: timestamp(),
            time_flow_end_ns: timestamp(),
            bytes: UInt64Builder::new(),
            packets: UInt64Builder::new(),
            src_addr: FixedSizeBinaryBuilder::new(IP_ADDR_LEN),
            dst_addr: FixedSizeBinaryBuilder::new(IP_ADDR_LEN),
            src_mac: FixedSizeBinaryBuilder::new(MAC_ADDR_LEN),
            dst_mac: FixedSizeBinaryBuilder::new(MAC_ADDR_LEN),
            etype: UInt16Builder::new(),
            proto: UInt8Builder::new(),
            src_port: UInt16Builder::new(),
            dst_port: UInt16Builder::new(),
            in_if: UInt32Builder::new(),
            out_if: UInt32Builder::new(),
            ip_tos: UInt8Builder::new(),
            ip_ttl: UInt8Builder::new(),
            tcp_flags: UInt8Builder::new(),
            icmp_type: UInt8Builder::new(),
            icmp_code: UInt8Builder::new(),
            ipv6_flow_label: UInt32Builder::new(),
            fragment_id: UInt32Builder::new(),
            fragment_offset: UInt16Builder::new(),
            src_as: UInt32Builder::new(),
            dst_as: UInt32Builder::new(),
            next_hop: FixedSizeBinaryBuilder::new(IP_ADDR_LEN),
            src_net: UInt8Builder::new(),
            dst_net: UInt8Builder::new(),
            bgp_next_hop: FixedSizeBinaryBuilder::new(IP_ADDR_LEN),
            src_vlan: UInt16Builder::new(),
            dst_vlan: UInt16Builder::new(),
            observation_domain_id: UInt32Builder::new(),
            template_id: UInt16Builder::new(),
            enriched: (0..enriched_count).map(|_| StringBuilder::new()).collect(),
        }
    }

    /// Drain every builder into column arrays, in schema order.
    fn finish(&mut self) -> Vec<ArrayRef> {
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(self.flow_type.finish()),
            Arc::new(self.time_received_ns.finish()),
            Arc::new(self.sequence_num.finish()),
            Arc::new(self.sampling_rate.finish()),
            Arc::new(self.sampler_address.finish()),
            Arc::new(self.time_flow_start_ns.finish()),
            Arc::new(self.time_flow_end_ns.finish()),
            Arc::new(self.bytes.finish()),
            Arc::new(self.packets.finish()),
            Arc::new(self.src_addr.finish()),
            Arc::new(self.dst_addr.finish()),
            Arc::new(self.src_mac.finish()),
            Arc::new(self.dst_mac.finish()),
            Arc::new(self.etype.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.in_if.finish()),
            Arc::new(self.out_if.finish()),
            Arc::new(self.ip_tos.finish()),
            Arc::new(self.ip_ttl.finish()),
            Arc::new(self.tcp_flags.finish()),
            Arc::new(self.icmp_type.finish()),
            Arc::new(self.icmp_code.finish()),
            Arc::new(self.ipv6_flow_label.finish()),
            Arc::new(self.fragment_id.finish()),
            Arc::new(self.fragment_offset.finish()),
            Arc::new(self.src_as.finish()),
            Arc::new(self.dst_as.finish()),
            Arc::new(self.next_hop.finish()),
            Arc::new(self.src_net.finish()),
            Arc::new(self.dst_net.finish()),
            Arc::new(self.bgp_next_hop.finish()),
            Arc::new(self.src_vlan.finish()),
            Arc::new(self.dst_vlan.finish()),
            Arc::new(self.observation_domain_id.finish()),
            Arc::new(self.template_id.finish()),
        ];
        for builder in &mut self.enriched {
            columns.push(Arc::new(builder.finish()));
        }
        columns
    }
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
