use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::sync::Mutex;

use csv::Writer as CsvWriter;
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use crate::SerializationFormat;

enum WriterKind {
    Json(BufWriter<Box<dyn Write + Send>>),
    Csv(CsvWriter<Box<dyn Write + Send>>),
}

pub struct OutputWriter {
    writer: Mutex<WriterKind>,
    enriched_fields: Vec<String>,
}

impl OutputWriter {
    pub fn new(
        file_path: Option<&str>,
        serialization: SerializationFormat,
        enriched_fields: &[String],
    ) -> io::Result<Self> {
        let output: Box<dyn Write + Send> = match file_path {
            Some(path) => Box::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?,
            ),
            None => Box::new(io::stdout()),
        };

        let writer = match serialization {
            SerializationFormat::Json => WriterKind::Json(BufWriter::new(output)),
            SerializationFormat::Csv => {
                let mut w = CsvWriter::from_writer(output);
                // Write headers: common flow fields + enriched fields
                let mut headers: Vec<&str> = COMMON_FLOW_HEADERS.to_vec();
                for field in enriched_fields {
                    headers.push(field.as_str());
                }
                w.write_record(&headers)?;
                WriterKind::Csv(w)
            }
        };

        Ok(Self {
            writer: Mutex::new(writer),
            enriched_fields: enriched_fields.to_vec(),
        })
    }

    pub fn write_enriched_flow(&self, flow: &CommonFlow, enriched: &HashMap<String, String>) {
        let mut writer = self.writer.lock().unwrap();
        match &mut *writer {
            WriterKind::Json(w) => {
                // Combine flow and enriched fields into a single JSON object
                if let Ok(mut flow_value) = serde_json::to_value(flow) {
                    if let serde_json::Value::Object(ref mut map) = flow_value {
                        for (key, value) in enriched {
                            map.insert(key.clone(), serde_json::Value::String(value.clone()));
                        }
                    }
                    if let Ok(json) = serde_json::to_string_pretty(&flow_value) {
                        writeln!(w, "{}", json).ok();
                        w.flush().ok();
                    }
                }
            }
            WriterKind::Csv(w) => {
                // Serialize flow first, then append enriched fields
                // We need to serialize the flow to CSV record format
                let flow_record = flow_to_csv_record(flow);
                let mut record = flow_record;

                // Append enriched fields in order
                for field_name in &self.enriched_fields {
                    record.push(enriched.get(field_name).cloned().unwrap_or_default());
                }

                w.write_record(&record).ok();
                w.flush().ok();
            }
        }
    }

    pub fn write_raw<T: Serialize>(&self, record: &T) {
        let mut writer = self.writer.lock().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(record) {
            match &mut *writer {
                WriterKind::Json(w) => {
                    writeln!(w, "{}", json).ok();
                    w.flush().ok();
                }
                WriterKind::Csv(_) => {
                    unreachable!("write_raw should not be called with CSV writer");
                }
            }
        }
    }
}

/// Convert CommonFlow to CSV record (vector of strings in header order)
fn flow_to_csv_record(flow: &CommonFlow) -> Vec<String> {
    vec![
        format!("{:?}", flow.flow_type),
        flow.time_received_ns.map(|v| v.to_string()).unwrap_or_default(),
        flow.sequence_num.to_string(),
        flow.sampling_rate.map(|v| v.to_string()).unwrap_or_default(),
        flow.sampler_address.map(|v| v.to_string()).unwrap_or_default(),
        flow.time_flow_start_ns.map(|v| v.to_string()).unwrap_or_default(),
        flow.time_flow_end_ns.map(|v| v.to_string()).unwrap_or_default(),
        flow.bytes.to_string(),
        flow.packets.to_string(),
        flow.src_addr.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_addr.map(|v| v.to_string()).unwrap_or_default(),
        flow.src_mac.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_mac.map(|v| v.to_string()).unwrap_or_default(),
        flow.etype.map(|v| v.to_string()).unwrap_or_default(),
        flow.proto.map(|v| v.to_string()).unwrap_or_default(),
        flow.src_port.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_port.map(|v| v.to_string()).unwrap_or_default(),
        flow.in_if.map(|v| v.to_string()).unwrap_or_default(),
        flow.out_if.map(|v| v.to_string()).unwrap_or_default(),
        flow.ip_tos.map(|v| v.to_string()).unwrap_or_default(),
        flow.ip_ttl.map(|v| v.to_string()).unwrap_or_default(),
        flow.tcp_flags.map(|v| v.to_string()).unwrap_or_default(),
        flow.icmp_type.map(|v| v.to_string()).unwrap_or_default(),
        flow.icmp_code.map(|v| v.to_string()).unwrap_or_default(),
        flow.ipv6_flow_label.map(|v| v.to_string()).unwrap_or_default(),
        flow.fragment_id.map(|v| v.to_string()).unwrap_or_default(),
        flow.fragment_offset.map(|v| v.to_string()).unwrap_or_default(),
        flow.src_as.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_as.map(|v| v.to_string()).unwrap_or_default(),
        flow.next_hop.map(|v| v.to_string()).unwrap_or_default(),
        flow.src_net.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_net.map(|v| v.to_string()).unwrap_or_default(),
        flow.bgp_next_hop.map(|v| v.to_string()).unwrap_or_default(),
        flow.src_vlan.map(|v| v.to_string()).unwrap_or_default(),
        flow.dst_vlan.map(|v| v.to_string()).unwrap_or_default(),
        flow.observation_domain_id.map(|v| v.to_string()).unwrap_or_default(),
    ]
}

const COMMON_FLOW_HEADERS: &[&str] = &[
    "flow_type",
    "time_received_ns",
    "sequence_num",
    "sampling_rate",
    "sampler_address",
    "time_flow_start_ns",
    "time_flow_end_ns",
    "bytes",
    "packets",
    "src_addr",
    "dst_addr",
    "src_mac",
    "dst_mac",
    "etype",
    "proto",
    "src_port",
    "dst_port",
    "in_if",
    "out_if",
    "ip_tos",
    "ip_ttl",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "ipv6_flow_label",
    "fragment_id",
    "fragment_offset",
    "src_as",
    "dst_as",
    "next_hop",
    "src_net",
    "dst_net",
    "bgp_next_hop",
    "src_vlan",
    "dst_vlan",
    "observation_domain_id",
];
