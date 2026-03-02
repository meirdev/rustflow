use std::collections::HashMap;
use std::fmt::Display;
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

fn opt_str<T: Display>(value: &Option<T>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn flow_to_csv_record(flow: &CommonFlow) -> Vec<String> {
    vec![
        flow.flow_type.to_string(),
        opt_str(&flow.time_received_ns),
        flow.sequence_num.to_string(),
        opt_str(&flow.sampling_rate),
        opt_str(&flow.sampler_address),
        opt_str(&flow.time_flow_start_ns),
        opt_str(&flow.time_flow_end_ns),
        flow.bytes.to_string(),
        flow.packets.to_string(),
        opt_str(&flow.src_addr),
        opt_str(&flow.dst_addr),
        opt_str(&flow.src_mac),
        opt_str(&flow.dst_mac),
        opt_str(&flow.etype),
        opt_str(&flow.proto),
        opt_str(&flow.src_port),
        opt_str(&flow.dst_port),
        opt_str(&flow.in_if),
        opt_str(&flow.out_if),
        opt_str(&flow.ip_tos),
        opt_str(&flow.ip_ttl),
        opt_str(&flow.tcp_flags),
        opt_str(&flow.icmp_type),
        opt_str(&flow.icmp_code),
        opt_str(&flow.ipv6_flow_label),
        opt_str(&flow.fragment_id),
        opt_str(&flow.fragment_offset),
        opt_str(&flow.src_as),
        opt_str(&flow.dst_as),
        opt_str(&flow.next_hop),
        opt_str(&flow.src_net),
        opt_str(&flow.dst_net),
        opt_str(&flow.bgp_next_hop),
        opt_str(&flow.src_vlan),
        opt_str(&flow.dst_vlan),
        opt_str(&flow.observation_domain_id),
        opt_str(&flow.template_id),
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
    "template_id",
];
