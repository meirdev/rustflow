use std::collections::HashMap;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use csv::Writer as CsvWriter;
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use crate::SerializationFormat;
use crate::parquet_sink::ParquetSink;

enum WriterKind {
    Ndjson(BufWriter<Box<dyn Write + Send>>),
    Csv(CsvWriter<Box<dyn Write + Send>>),
    Parquet(ParquetSink),
}

impl WriterKind {
    /// Flush buffered data and, for Parquet, write the file footer.
    fn finish(&mut self) {
        match self {
            WriterKind::Ndjson(w) => {
                w.flush().ok();
            }
            WriterKind::Csv(w) => {
                w.flush().ok();
            }
            WriterKind::Parquet(w) => {
                if let Err(e) = w.finish() {
                    eprintln!("Failed to finalize parquet file: {}", e);
                }
            }
        }
    }
}

/// Deepest supported directory partitioning level.
pub const MAX_PARTITION_LEVEL: u8 = 3;

/// Directory resolution, in minutes, of the deepest partitioning level.
const LEVEL_3_MINUTES: u32 = 5;

enum Destination {
    Stdout,
    /// A single file that is never rotated.
    File(PathBuf),
    /// A directory tree that one file per interval is partitioned into.
    Directory {
        root: PathBuf,
        level: u8,
        prefix: String,
        extension: &'static str,
    },
}

struct State {
    writer: WriterKind,
    /// Unix timestamp at which the current file must be rotated, if an
    /// interval is configured.
    rotate_at: Option<i64>,
}

/// How and where flows are written.
pub struct OutputOptions<'a> {
    /// Output path: a file when `interval` is `None`, otherwise the root
    /// directory of the partitioned tree. `None` writes to stdout.
    pub path: Option<&'a str>,
    pub serialization: SerializationFormat,
    pub enriched_fields: &'a [String],
    /// Start a new file every interval. `None` writes a single file.
    pub interval: Option<Duration>,
    /// Directory partitioning level, see [`partition_path`].
    pub level: u8,
    /// File name prefix inside the partitioned tree.
    pub prefix: &'a str,
}

pub struct OutputWriter {
    state: Mutex<State>,
    destination: Destination,
    serialization: SerializationFormat,
    enriched_fields: Vec<String>,
    /// Rotation interval in whole seconds; `None` writes a single file.
    interval_secs: Option<i64>,
}

impl OutputWriter {
    pub fn new(options: OutputOptions) -> io::Result<Self> {
        let OutputOptions {
            path,
            serialization,
            enriched_fields,
            interval,
            level,
            prefix,
        } = options;

        // An interval turns the output path into a directory tree; without
        // one, everything goes to a single file (or stdout).
        let destination = match (path, interval) {
            (None, _) => Destination::Stdout,
            (Some(path), None) => Destination::File(PathBuf::from(path)),
            (Some(root), Some(_)) => Destination::Directory {
                root: PathBuf::from(root),
                level: level.min(MAX_PARTITION_LEVEL),
                prefix: prefix.to_string(),
                extension: file_extension(serialization),
            },
        };

        let interval_secs = match destination {
            Destination::Directory { .. } => interval.map(|d| d.as_secs().max(1) as i64),
            Destination::File(_) | Destination::Stdout => None,
        };

        let (writer, rotate_at) = create_writer(
            &destination,
            serialization,
            enriched_fields,
            interval_secs,
            Utc::now(),
        )?;

        Ok(Self {
            state: Mutex::new(State { writer, rotate_at }),
            destination,
            serialization,
            enriched_fields: enriched_fields.to_vec(),
            interval_secs,
        })
    }

    pub fn write_enriched_flow(&self, flow: &CommonFlow, enriched: &HashMap<String, String>) {
        let mut state = self.state.lock().unwrap();
        self.rotate_if_due(&mut state);

        match &mut state.writer {
            WriterKind::Ndjson(w) => {
                // Combine flow and enriched fields into a single JSON object
                if let Ok(mut flow_value) = serde_json::to_value(flow) {
                    if let serde_json::Value::Object(ref mut map) = flow_value {
                        for (key, value) in enriched {
                            map.insert(key.clone(), serde_json::Value::String(value.clone()));
                        }
                    }
                    if let Ok(json) = serde_json::to_string(&flow_value) {
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
            WriterKind::Parquet(w) => {
                if let Err(e) = w.write(flow, enriched) {
                    eprintln!("Failed to write parquet record: {}", e);
                }
            }
        }
    }

    pub fn write_raw<T: Serialize>(&self, record: &T) {
        let mut state = self.state.lock().unwrap();
        self.rotate_if_due(&mut state);

        if let Ok(json) = serde_json::to_string(record) {
            match &mut state.writer {
                WriterKind::Ndjson(w) => {
                    writeln!(w, "{}", json).ok();
                    w.flush().ok();
                }
                WriterKind::Csv(_) | WriterKind::Parquet(_) => {
                    unreachable!("write_raw only supports the ndjson serialization format");
                }
            }
        }
    }

    /// Flush buffered data and finalize the current file.
    ///
    /// Required before exiting when the Parquet serialization is used, since
    /// the file footer is only written on close.
    pub fn finish(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.writer.finish();
        }
    }

    /// Close the current file and start a new one when the rotation window has
    /// elapsed.
    fn rotate_if_due(&self, state: &mut State) {
        let (Some(rotate_at), Some(interval_secs)) = (state.rotate_at, self.interval_secs) else {
            return;
        };

        let now = Utc::now();
        if now.timestamp() < rotate_at {
            return;
        }

        match create_writer(
            &self.destination,
            self.serialization,
            &self.enriched_fields,
            self.interval_secs,
            now,
        ) {
            Ok((writer, next_rotate_at)) => {
                let mut previous = std::mem::replace(&mut state.writer, writer);
                previous.finish();
                state.rotate_at = next_rotate_at;
            }
            Err(e) => {
                // Keep writing to the current file and try again next window.
                eprintln!("Failed to rotate output file: {}", e);
                state.rotate_at = Some(rotate_at + interval_secs);
            }
        }
    }
}

impl Drop for OutputWriter {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Open the sink for the window containing `now` and return it together with
/// the timestamp of the next rotation (`None` when rotation is disabled).
fn create_writer(
    destination: &Destination,
    serialization: SerializationFormat,
    enriched_fields: &[String],
    interval_secs: Option<i64>,
    now: DateTime<Utc>,
) -> io::Result<(WriterKind, Option<i64>)> {
    let (path, rotate_at) = match destination {
        Destination::Stdout => (None, None),
        Destination::File(path) => (Some(path.clone()), None),
        Destination::Directory {
            root,
            level,
            prefix,
            extension,
        } => {
            let secs = interval_secs.unwrap_or(1).max(1);
            // Align windows to the epoch so file names land on round
            // boundaries (e.g. the top of every hour for `1h`).
            let window_start = now.timestamp().div_euclid(secs) * secs;
            let stamp = DateTime::from_timestamp(window_start, 0).unwrap_or(now);
            (
                Some(partition_path(root, *level, prefix, extension, stamp)),
                Some(window_start + secs),
            )
        }
    };

    let output: Box<dyn Write + Send> = match &path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Box::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?,
            )
        }
        None => Box::new(io::stdout()),
    };

    let writer = match serialization {
        SerializationFormat::Ndjson => WriterKind::Ndjson(BufWriter::new(output)),
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
        SerializationFormat::Parquet => WriterKind::Parquet(
            ParquetSink::new(output, enriched_fields).map_err(io::Error::other)?,
        ),
    };

    Ok((writer, rotate_at))
}

/// Build the path of the file holding the interval window starting at
/// `stamp`.
///
/// The window start is partitioned into directories below `root`:
///
/// | Level | Layout                                    |
/// | ----- | ----------------------------------------- |
/// | 0     | `root/`                                   |
/// | 1     | `root/%Y/%m/%d/`                          |
/// | 2     | `root/%Y/%m/%d/%H/`                       |
/// | 3     | `root/%Y/%m/%d/%H/%M/` in 5 minute steps  |
///
/// The file itself is named `<prefix>-<window start>.<extension>`, e.g.
/// `flows-20240102T150500Z.parquet`.
fn partition_path(
    root: &Path,
    level: u8,
    prefix: &str,
    extension: &str,
    stamp: DateTime<Utc>,
) -> PathBuf {
    let mut path = root.to_path_buf();

    if level >= 1 {
        path.push(stamp.format("%Y").to_string());
        path.push(stamp.format("%m").to_string());
        path.push(stamp.format("%d").to_string());
    }
    if level >= 2 {
        path.push(stamp.format("%H").to_string());
    }
    if level >= 3 {
        // Floor to the enclosing 5 minute bucket: 00, 05, ... 55.
        path.push(format!(
            "{:02}",
            stamp.minute() / LEVEL_3_MINUTES * LEVEL_3_MINUTES
        ));
    }

    path.push(format!(
        "{}-{}.{}",
        prefix,
        stamp.format("%Y%m%dT%H%M%SZ"),
        extension
    ));
    path
}

/// File extension used for generated file names.
fn file_extension(serialization: SerializationFormat) -> &'static str {
    match serialization {
        SerializationFormat::Ndjson => "ndjson",
        SerializationFormat::Csv => "csv",
        SerializationFormat::Parquet => "parquet",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// 2024-01-02T15:07:00Z
    const SAMPLE: i64 = 1_704_208_020;

    #[test]
    fn partition_level_0_writes_flat_into_the_root() {
        let path = partition_path(Path::new("/data"), 0, "flows", "parquet", stamp(SAMPLE));
        assert_eq!(path, PathBuf::from("/data/flows-20240102T150700Z.parquet"));
    }

    #[test]
    fn partition_level_1_is_day_resolution() {
        let path = partition_path(Path::new("/data"), 1, "flows", "ndjson", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/flows-20240102T150700Z.ndjson")
        );
    }

    #[test]
    fn partition_level_2_is_hour_resolution() {
        let path = partition_path(Path::new("/data"), 2, "flows", "csv", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/flows-20240102T150700Z.csv")
        );
    }

    #[test]
    fn partition_level_3_floors_to_five_minute_buckets() {
        let path = partition_path(Path::new("/data"), 3, "flows", "parquet", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/05/flows-20240102T150700Z.parquet")
        );

        // The top of the hour lands in the `00` bucket.
        let path = partition_path(
            Path::new("/data"),
            3,
            "flows",
            "parquet",
            stamp(SAMPLE - 420),
        );
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/00/flows-20240102T150000Z.parquet")
        );
    }

    #[test]
    fn partition_path_honours_the_prefix() {
        let path = partition_path(Path::new("out"), 1, "edge01", "parquet", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("out/2024/01/02/edge01-20240102T150700Z.parquet")
        );
    }
}
