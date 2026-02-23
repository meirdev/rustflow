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
}

impl OutputWriter {
    pub fn new(file_path: Option<&str>, serialization: SerializationFormat) -> io::Result<Self> {
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
                w.write_record(COMMON_FLOW_HEADERS)?;
                WriterKind::Csv(w)
            }
        };

        Ok(Self {
            writer: Mutex::new(writer),
        })
    }

    pub fn write_common_flow(&self, flow: &CommonFlow) {
        let mut writer = self.writer.lock().unwrap();
        match &mut *writer {
            WriterKind::Json(w) => {
                if let Ok(json) = serde_json::to_string_pretty(flow) {
                    writeln!(w, "{}", json).ok();
                    w.flush().ok();
                }
            }
            WriterKind::Csv(w) => {
                w.serialize(flow).ok();
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
    "etype",
    "proto",
    "src_port",
    "dst_port",
    "in_if",
    "out_if",
    "src_mac",
    "dst_mac",
    "src_vlan",
    "dst_vlan",
    "vlan_id",
    "ip_tos",
    "forwarding_status",
    "ip_ttl",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "ipv6_flow_label",
    "fragment_id",
    "fragment_offset",
    "bi_flow_direction",
    "src_as",
    "dst_as",
    "next_hop",
    "next_hop_as",
    "src_net",
    "dst_net",
];
