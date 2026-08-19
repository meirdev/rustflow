use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
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
    /// Flush buffered data without ending the file. Parquet batches its own
    /// rows and has nothing to flush until a row group is complete.
    fn flush(&mut self) {
        match self {
            WriterKind::Ndjson(w) => {
                w.flush().ok();
            }
            WriterKind::Csv(w) => {
                w.flush().ok();
            }
            WriterKind::Parquet(_) => {}
        }
    }

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

/// Buffer size for the text writers. Records are not flushed individually, so
/// this is what bounds how often the collector calls into the kernel.
const WRITE_BUFFER_BYTES: usize = 256 * 1024;

/// How often the background thread flushes buffered output. This bounds how
/// stale a line can be when flows trickle in too slowly to fill the buffer.
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

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
    /// Set when a record has been written but not yet flushed, so the
    /// background flusher can skip the syscall while the collector is idle.
    dirty: bool,
    /// Reusable buffer for serializing one NDJSON line.
    line: Vec<u8>,
    /// Reusable CSV field buffers, kept to hold onto their allocations.
    fields: Vec<String>,
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
            state: Mutex::new(State {
                writer,
                rotate_at,
                dirty: false,
                line: Vec::with_capacity(1024),
                fields: Vec::new(),
            }),
            destination,
            serialization,
            enriched_fields: enriched_fields.to_vec(),
            interval_secs,
        })
    }

    /// Start the background thread that flushes buffered output every
    /// [`FLUSH_INTERVAL`].
    ///
    /// The thread holds a [`Weak`] reference so that dropping the last
    /// [`Arc<OutputWriter>`] still runs `Drop` and finalizes the file — an
    /// owning reference here would keep a Parquet footer from ever being
    /// written when reading a pcap.
    pub fn spawn_flusher(writer: &Arc<Self>) {
        let weak = Arc::downgrade(writer);
        std::thread::spawn(move || flush_loop(weak));
    }

    pub fn write_enriched_flow(&self, flow: &CommonFlow, enriched: &HashMap<String, String>) {
        let mut state = self.state.lock().unwrap();
        self.rotate_if_due(&mut state);

        let State {
            writer,
            line,
            fields,
            ..
        } = &mut *state;

        match writer {
            WriterKind::Ndjson(w) => {
                if self.enriched_fields.is_empty() {
                    // Serialize straight into the output buffer: no
                    // intermediate `Value` tree and no temporary String.
                    if serde_json::to_writer(&mut *w, flow).is_ok() {
                        w.write_all(b"\n").ok();
                    }
                } else {
                    write_enriched_json_line(line, flow, &self.enriched_fields, enriched);
                    w.write_all(line).ok();
                }
            }
            WriterKind::Csv(w) => {
                write_csv_record(fields, flow, &self.enriched_fields, enriched);
                w.write_record(fields.iter()).ok();
            }
            WriterKind::Parquet(w) => {
                if let Err(e) = w.write(flow, enriched) {
                    eprintln!("Failed to write parquet record: {}", e);
                }
            }
        }
        state.dirty = true;
    }

    pub fn write_raw<T: Serialize>(&self, record: &T) {
        let mut state = self.state.lock().unwrap();
        self.rotate_if_due(&mut state);

        match &mut state.writer {
            WriterKind::Ndjson(w) => {
                if serde_json::to_writer(&mut *w, record).is_ok() {
                    w.write_all(b"\n").ok();
                }
            }
            WriterKind::Csv(_) | WriterKind::Parquet(_) => {
                unreachable!("write_raw only supports the ndjson serialization format");
            }
        }
        state.dirty = true;
    }

    /// Flush buffered data and finalize the current file.
    ///
    /// Required before exiting when the Parquet serialization is used, since
    /// the file footer is only written on close.
    pub fn finish(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.writer.finish();
            state.dirty = false;
        }
    }

    /// Flush whatever is buffered, if anything has been written since the last
    /// flush. Called by the background flusher.
    fn flush_if_dirty(&self) {
        if let Ok(mut state) = self.state.lock()
            && state.dirty
        {
            state.writer.flush();
            state.dirty = false;
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

/// Flush buffered output periodically until the writer is dropped.
fn flush_loop(writer: Weak<OutputWriter>) {
    loop {
        std::thread::sleep(FLUSH_INTERVAL);
        match writer.upgrade() {
            Some(writer) => writer.flush_if_dirty(),
            // The collector is shutting down and has already finalized.
            None => return,
        }
    }
}

/// Serialize one flow plus its enrichment fields as a single JSON object,
/// followed by a newline, into `line`.
///
/// Serde has no public way to splice extra keys into a struct's output, so the
/// flow is serialized first and the enrichment fields are appended before the
/// closing brace. Keys and values still go through `serde_json` so escaping is
/// handled properly.
fn write_enriched_json_line(
    line: &mut Vec<u8>,
    flow: &CommonFlow,
    enriched_fields: &[String],
    enriched: &HashMap<String, String>,
) {
    line.clear();
    if serde_json::to_writer(&mut *line, flow).is_err() {
        return;
    }

    // Reopen the object to append the enrichment fields.
    debug_assert_eq!(line.last(), Some(&b'}'));
    line.pop();

    for name in enriched_fields {
        let Some(value) = enriched.get(name) else {
            continue;
        };
        line.push(b',');
        serde_json::to_writer(&mut *line, name).ok();
        line.push(b':');
        serde_json::to_writer(&mut *line, value).ok();
    }

    line.push(b'}');
    line.push(b'\n');
}

/// Render one flow plus its enrichment fields into `fields`, reusing each
/// field's existing allocation.
fn write_csv_record(
    fields: &mut Vec<String>,
    flow: &CommonFlow,
    enriched_fields: &[String],
    enriched: &HashMap<String, String>,
) {
    let needed = COMMON_FLOW_HEADERS.len() + enriched_fields.len();
    if fields.len() < needed {
        fields.resize_with(needed, String::new);
    }
    for field in fields.iter_mut() {
        field.clear();
    }

    let mut i = 0;
    /// Write a required field.
    macro_rules! put {
        ($value:expr) => {{
            write!(fields[i], "{}", $value).ok();
            i += 1;
        }};
    }
    /// Write an optional field; `None` leaves the field empty.
    macro_rules! put_opt {
        ($value:expr) => {{
            if let Some(value) = &$value {
                write!(fields[i], "{}", value).ok();
            }
            i += 1;
        }};
    }

    put!(flow.flow_type);
    put_opt!(flow.time_received_ns);
    put!(flow.sequence_num);
    put_opt!(flow.sampling_rate);
    put_opt!(flow.sampler_address);
    put_opt!(flow.time_flow_start_ns);
    put_opt!(flow.time_flow_end_ns);
    put!(flow.bytes);
    put!(flow.packets);
    put_opt!(flow.src_addr);
    put_opt!(flow.dst_addr);
    put_opt!(flow.src_mac);
    put_opt!(flow.dst_mac);
    put_opt!(flow.etype);
    put_opt!(flow.proto);
    put_opt!(flow.src_port);
    put_opt!(flow.dst_port);
    put_opt!(flow.in_if);
    put_opt!(flow.out_if);
    put_opt!(flow.ip_tos);
    put_opt!(flow.ip_ttl);
    put_opt!(flow.tcp_flags);
    put_opt!(flow.icmp_type);
    put_opt!(flow.icmp_code);
    put_opt!(flow.ipv6_flow_label);
    put_opt!(flow.fragment_id);
    put_opt!(flow.fragment_offset);
    put_opt!(flow.src_as);
    put_opt!(flow.dst_as);
    put_opt!(flow.next_hop);
    put_opt!(flow.src_net);
    put_opt!(flow.dst_net);
    put_opt!(flow.bgp_next_hop);
    put_opt!(flow.src_vlan);
    put_opt!(flow.dst_vlan);
    put_opt!(flow.observation_domain_id);
    put_opt!(flow.template_id);

    debug_assert_eq!(i, COMMON_FLOW_HEADERS.len());

    for name in enriched_fields {
        if let Some(value) = enriched.get(name) {
            fields[i].push_str(value);
        }
        i += 1;
    }

    fields.truncate(needed);
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
        SerializationFormat::Ndjson => {
            WriterKind::Ndjson(BufWriter::with_capacity(WRITE_BUFFER_BYTES, output))
        }
        SerializationFormat::Csv => {
            let mut w = csv::WriterBuilder::new()
                .buffer_capacity(WRITE_BUFFER_BYTES)
                .from_writer(output);
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

    fn sample_flow() -> CommonFlow {
        use std::net::{IpAddr, Ipv4Addr};

        use rustflow_core::common::common_flow::FlowType;
        let mut flow = CommonFlow::new(FlowType::Ipfix);
        flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        flow.src_port = Some(443);
        flow.bytes = 1234;
        // dst_addr and most other fields stay None
        flow
    }

    #[test]
    fn enriched_json_line_is_valid_json_with_the_extra_keys() {
        let fields = vec!["src_asn".to_string(), "src_org".to_string()];
        let mut enriched = HashMap::new();
        enriched.insert("src_asn".to_string(), "13335".to_string());
        // a value that must be escaped, and would corrupt the object if spliced raw
        enriched.insert("src_org".to_string(), "Cloud \"Net\", Inc.\\x".to_string());

        let mut line = Vec::new();
        write_enriched_json_line(&mut line, &sample_flow(), &fields, &enriched);

        assert_eq!(line.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&line).expect("valid JSON");
        assert_eq!(value["src_asn"], "13335");
        assert_eq!(value["src_org"], "Cloud \"Net\", Inc.\\x");
        assert_eq!(value["src_port"], 443);
        assert_eq!(value["flow_type"], "IPFIX");
    }

    #[test]
    fn enriched_json_line_omits_absent_fields_and_reuses_the_buffer() {
        let fields = vec!["src_asn".to_string()];
        let mut line = Vec::new();

        write_enriched_json_line(&mut line, &sample_flow(), &fields, &HashMap::new());
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert!(value.get("src_asn").is_none());

        // writing again must not append to the previous line
        let mut enriched = HashMap::new();
        enriched.insert("src_asn".to_string(), "64512".to_string());
        write_enriched_json_line(&mut line, &sample_flow(), &fields, &enriched);
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(value["src_asn"], "64512");
    }

    #[test]
    fn csv_record_matches_the_header_width() {
        let fields = vec!["src_asn".to_string(), "src_org".to_string()];
        let mut enriched = HashMap::new();
        enriched.insert("src_asn".to_string(), "13335".to_string());

        let mut buf = Vec::new();
        write_csv_record(&mut buf, &sample_flow(), &fields, &enriched);

        assert_eq!(buf.len(), COMMON_FLOW_HEADERS.len() + fields.len());
        assert_eq!(buf[0], "IPFIX");
        assert_eq!(buf[7], "1234");
        // an absent optional field stays empty
        assert_eq!(buf[10], "");
        assert_eq!(buf[COMMON_FLOW_HEADERS.len()], "13335");
        // an enrichment field with no value stays empty
        assert_eq!(buf[COMMON_FLOW_HEADERS.len() + 1], "");
    }

    #[test]
    fn csv_record_does_not_leak_values_between_flows() {
        let fields: Vec<String> = Vec::new();
        let mut buf = Vec::new();
        let mut flow = sample_flow();
        write_csv_record(&mut buf, &flow, &fields, &HashMap::new());
        assert_eq!(buf[9], "10.1.2.3");

        flow.src_addr = None;
        flow.bytes = 7;
        write_csv_record(&mut buf, &flow, &fields, &HashMap::new());
        assert_eq!(buf[9], "", "stale value from the previous record");
        assert_eq!(buf[7], "7");
    }

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
