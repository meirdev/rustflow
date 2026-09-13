# rustflow_collect: sink / output redesign plan

Scope: `crates/rustflow_collect` only. Nothing in `rustflow_core` or `rustflow`
changes. The CLI flags and file layouts stay identical.

Output compatibility guarantee, per format (see section 12 for the tests):

| Format | Guarantee | Why not stricter |
| --- | --- | --- |
| NDJSON, CSV | byte-identical | |
| Parquet | identical schema and decoded rows | the footer carries a `created_by` string that changes with the arrow/parquet crate version |
| Protobuf, no enrichment | byte-identical | |
| Protobuf, with enrichment | identical decoded message | today's derived encoder iterates a `HashMap`, so map entry order already differs from run to run |

The existing e2e tests in `tests/` only parse NDJSON from stdout in pcap
mode. They are **not** a multi-format guard; step 0 of the migration
(section 11) adds one before anything moves.

Goals, in priority order:

1. **Design**: one responsibility per type, one place to add a format.
2. **Idiomatic Rust**: ownership instead of `Mutex` + `Arc` + `Weak`, `Result`
   instead of `.ok()`, types instead of `unreachable!`.
3. **Performance**: per-chunk instead of per-flow overhead, zero per-flow
   allocation in every encoder.

---

## 1. What the current code does, and where it hurts

`output.rs` (875 lines) holds a single `OutputWriter` that does five jobs:

| Job | Where | Problem |
| --- | --- | --- |
| Format encoding | `WriterKind` enum, 5 variants | Every method is a `match`; a new format touches 6 places |
| Destination | `Destination` enum + `create_writer` | Mixed into the same function as encoder construction |
| Rotation policy | `rotate_if_due`, `pending_rename` | Runs per flow, calls `Utc::now()` per flow, never fires on an idle window |
| Background flush | `spawn_flusher`, `flush_loop`, `Weak` | Exists only because the sink is shared; forces `Mutex<State>` and `impl Drop` |
| Raw vs common | `write_raw` | `unreachable!()` for 3 of 5 formats; the invariant lives in `validate_cli` |

Other things worth fixing while there:

- **Five hand-written field lists** must agree: `COMMON_FLOW_HEADERS`, the CSV
  `put!` list, the Arrow schema, the Arrow builders (declared, constructed,
  finished), and `proto::CommonFlow::from_flow`. A new field in `CommonFlow`
  silently drops out of every format except JSON.
- **Errors are swallowed.** Almost every write ends in `.ok()`. A full disk
  means the collector runs forever writing nothing. There are no output
  metrics at all.
- **Per-flow costs**: mutex lock, `Utc::now()`, a `HashMap<String, String>`
  allocated by enrichment and hashed into by every encoder, and in the
  protobuf path 6 `Vec<u8>` + 1 `String` + 1 `HashMap` clone per flow.

---

## 2. Target layout

```
crates/rustflow_sink/src/          (as built, 2026-09-08)
  lib.rs          module tree and re-exports only
  flow/           what a flow looks like to the sink
    fields.rs       for_each_flow_field! (the one field list), Column, Value, visit
    enriched.rs     Enriched: positional enrichment values
  encoder/        layer 1: one flow -> bytes
    mod.rs          FlowEncoder, RawEncoder, Output
    ndjson.rs  csv.rs  parquet.rs (+ parquet/tests.rs)  protobuf.rs  discard.rs
    text.rs         AddrText: IP/MAC text without core::fmt
  sink/           layers 2 and 3
    mod.rs          FlowSink, RawSink, Format, SinkConfig, build(), build_raw()
    destination.rs  Stdout | File | Partitioned | Null; partition_path, temp/rename
    rotating.rs     RotatingSink<E>: the rotation state machine
    metrics.rs      OutputMetrics, CountingWriter
  pipeline/       the encoder thread
    mod.rs          encoder_loop, FLUSH_INTERVAL
    timer.rs        FlushTimer
    errors.rs       SinkErrors
```

Three layers, each unaware of the ones above it:

```
   encoder thread ──owns──> Box<dyn FlowSink>
                                 │
                        RotatingSink<E>          (when to open / close / rename files)
                          │           │
                    Destination     E: FlowEncoder   (how to turn a flow into bytes)
                (where bytes go)         │
                                  Box<dyn Write + Send>
```

---

## 3. The enrich -> sink contract: `Enriched`

Every encoder today receives `&HashMap<String, String>` and does
`enriched.get(name)` per output field per flow. The output field list is fixed
at startup, so the values should be positional and borrowed.

```rust
// sink/enriched.rs

/// Enrichment values for one flow, in the same order as
/// `EnrichmentEngine::output_fields()`. `None` means no match.
///
/// Owned by the encoder loop and refilled for every flow, so no allocation
/// happens per flow once the slots have been touched once.
pub struct Enriched {
    values: Vec<Option<Arc<str>>>,
}

impl Enriched {
    pub fn new(field_count: usize) -> Self {
        Self { values: vec![None; field_count] }
    }

    pub fn clear(&mut self) {
        self.values.iter_mut().for_each(|v| *v = None);
    }

    pub fn set(&mut self, index: usize, value: Arc<str>) {
        self.values[index] = Some(value);
    }

    pub fn iter(&self) -> impl Iterator<Item = Option<&str>> + '_ {
        self.values.iter().map(|v| v.as_deref())
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        self.values[index].as_deref()
    }
}
```

The engine side becomes `fn enrich_into(&self, flow: &CommonFlow, out: &mut Enriched)`
where each `FieldMapping` carries its resolved `output_index` instead of an
`output_field: String`, and the trie stores `Arc<str>` so a hit is a refcount
bump, not a `String` clone.

> If the enrich rewrite on the other machine already returns something else,
> adapt this: the only requirement from the sink side is *positional* and
> *`AsRef<str>`*. Every example below only uses `iter()` and `get(i)`.

---

## 4. Layer 1: `FlowEncoder`

One trait, one struct per format. An encoder owns a `Box<dyn Write + Send>`
and knows nothing about files, rotation, or threads.

```rust
// sink/encoder.rs
use std::io::{self, Write};
use rustflow_core::common::common_flow::CommonFlow;
use crate::sink::enriched::Enriched;

pub trait FlowEncoder: Send + Sized {
    /// File extension used by the partitioned tree (`flows-….<EXTENSION>`).
    const EXTENSION: &'static str;

    /// Start a new stream. Writes any header (CSV header row, Parquet
    /// schema) now, so a rotated file is well-formed even if empty.
    fn open(out: Box<dyn Write + Send>, enriched_fields: &[String]) -> io::Result<Self>;

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    /// Push buffered bytes to the destination without ending the stream.
    fn flush(&mut self) -> io::Result<()>;

    /// End the stream (Parquet footer). Consumes `self`, so "write after
    /// finish" is a compile error and needs no runtime guard.
    fn finish(self) -> io::Result<()>;
}
```

### 4.1 NDJSON

```rust
// sink/ndjson.rs
pub struct Ndjson {
    out: BufWriter<Box<dyn Write + Send>>,
    names: Vec<String>,
}

/// One output line: the flow's own fields plus the enrichment fields,
/// flattened into a single object. `serde_json` streams `flatten` through
/// `serialize_map`, so there is no intermediate `Value` tree.
#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    flow: &'a CommonFlow,
    #[serde(flatten)]
    enriched: EnrichedMap<'a>,
}

struct EnrichedMap<'a> {
    names: &'a [String],
    values: &'a Enriched,
}

impl Serialize for EnrichedMap<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (name, value) in self.names.iter().zip(self.values.iter()) {
            if let Some(value) = value {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

impl FlowEncoder for Ndjson {
    const EXTENSION: &'static str = "ndjson";

    fn open(out: Box<dyn Write + Send>, enriched_fields: &[String]) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(WRITE_BUFFER_BYTES, out),
            names: enriched_fields.to_vec(),
        })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        if self.names.is_empty() {
            serde_json::to_writer(&mut self.out, flow)?;      // fast path, no flatten
        } else {
            let row = Row { flow, enriched: EnrichedMap { names: &self.names, values: enriched } };
            serde_json::to_writer(&mut self.out, &row)?;
        }
        self.out.write_all(b"\n")
    }

    fn flush(&mut self) -> io::Result<()> { self.out.flush() }
    fn finish(mut self) -> io::Result<()> { self.out.flush() }
}

/// Raw mode (`--format raw`): any serializable packet, one per record.
/// A second, smaller trait: only the encoders that can carry an arbitrary
/// `Serialize` value implement it, which today is NDJSON and Discard. The
/// CLI rule "raw requires ndjson or discard" becomes a type constraint.
pub trait RawEncoder: FlowEncoder {
    fn write_value<T: Serialize>(&mut self, value: &T) -> io::Result<()>;
}

impl RawEncoder for Ndjson {
    fn write_value<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        serde_json::to_writer(&mut self.out, value)?;
        self.out.write_all(b"\n")
    }
}
```

The current "pop the closing brace and splice" trick can stay as a fallback
if the bench shows `flatten` costs anything. Keep the existing test
`enriched_json_line_is_valid_json_with_the_extra_keys`; it works unchanged
against `encode` writing into a `Vec<u8>`.

### 4.2 CSV

The CSV encoder decides how every value kind looks as text. The field list
(section 7) only tells it which values exist and in what order.

```rust
// sink/csv.rs
use std::fmt::Write as _;
use crate::sink::fields::{self, Value};

pub struct Csv {
    out: csv::Writer<Box<dyn Write + Send>>,
    scratch: String,      // reused for Display formatting, never reallocates after warm-up
}

/// Text form of one value. `None` leaves the field empty, as today.
fn write_text(scratch: &mut String, value: Value) {
    scratch.clear();
    match value {
        Value::FlowType(v)          => write!(scratch, "{v}").unwrap(),
        Value::U8(Some(v))          => write!(scratch, "{v}").unwrap(),
        Value::U16(Some(v))         => write!(scratch, "{v}").unwrap(),
        Value::U32(Some(v))         => write!(scratch, "{v}").unwrap(),
        Value::U64(Some(v))         => write!(scratch, "{v}").unwrap(),
        Value::TimestampNs(Some(v)) => write!(scratch, "{v}").unwrap(),
        Value::Ip(Some(v))          => write!(scratch, "{v}").unwrap(),
        Value::Mac(Some(v))         => write!(scratch, "{v}").unwrap(),
        Value::U8(None) | Value::U16(None) | Value::U32(None) | Value::U64(None)
        | Value::TimestampNs(None) | Value::Ip(None) | Value::Mac(None) => {}
    }
}

impl FlowEncoder for Csv {
    const EXTENSION: &'static str = "csv";

    fn open(out: Box<dyn Write + Send>, enriched_fields: &[String]) -> io::Result<Self> {
        let mut w = csv::WriterBuilder::new()
            .buffer_capacity(WRITE_BUFFER_BYTES)
            .from_writer(out);
        // Header: the flow's column names plus the enrichment names.
        let names = fields::columns().map(|c| c.name);
        w.write_record(names.chain(enriched_fields.iter().map(String::as_str)))?;
        Ok(Self { out: w, scratch: String::new() })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let Self { out, scratch } = self;
        // Flow fields go straight to write_field: no Vec<String> in between.
        fields::visit(flow, |_, value| {
            write_text(scratch, value);
            out.write_field(scratch.as_bytes())
        })?;
        for value in enriched.iter() {
            out.write_field(value.unwrap_or(""))?;
        }
        // Terminates the record started by write_field.
        out.write_record(None::<&[u8]>)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> { self.out.flush() }
    fn finish(mut self) -> io::Result<()> { self.out.flush() }
}
```

### 4.3 Parquet

Same behaviour as today's `ParquetSink`. Arrow types, builders, and the
`append` rules all stay in this file; they are derived from the field list
instead of being written out three times.

```rust
// sink/parquet.rs
use crate::sink::fields::{self, Column, Value};

pub struct Parquet {
    writer: ArrowWriter<Box<dyn Write + Send>>,      // no Option: finish() consumes self
    schema: Arc<Schema>,
    columns: Vec<Builder>,                           // flow columns then enrichment columns
    flow_column_count: usize,
    rows: usize,
}

/// One Arrow builder per column. This enum is private to the Parquet
/// encoder; nothing outside this file knows Arrow exists.
enum Builder {
    U8(UInt8Builder), U16(UInt16Builder), U32(UInt32Builder), U64(UInt64Builder),
    Ts(TimestampNanosecondBuilder), Text(StringBuilder),
}

/// How each value kind is typed and stored in Parquet. This is the one
/// place that decides "an IP address is a Utf8 column".
fn column_type(value: &Value) -> (DataType, Builder) {
    match value {
        Value::U8(_)          => (DataType::UInt8,  Builder::U8(UInt8Builder::new())),
        Value::U16(_)         => (DataType::UInt16, Builder::U16(UInt16Builder::new())),
        Value::U32(_)         => (DataType::UInt32, Builder::U32(UInt32Builder::new())),
        Value::U64(_)         => (DataType::UInt64, Builder::U64(UInt64Builder::new())),
        Value::TimestampNs(_) => (
            DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into())),
            Builder::Ts(TimestampNanosecondBuilder::new().with_timezone("UTC")),
        ),
        Value::FlowType(_) | Value::Ip(_) | Value::Mac(_) => {
            (DataType::Utf8, Builder::Text(StringBuilder::new()))
        }
    }
}

fn append(builder: &mut Builder, value: Value) {
    match (builder, value) {
        (Builder::U8(b),   Value::U8(v))          => b.append_option(v),
        (Builder::U16(b),  Value::U16(v))         => b.append_option(v),
        (Builder::U32(b),  Value::U32(v))         => b.append_option(v),
        (Builder::U64(b),  Value::U64(v))         => b.append_option(v),
        (Builder::Ts(b),   Value::TimestampNs(v)) => b.append_option(v),
        (Builder::Text(b), Value::FlowType(v))    => b.append_value(flow_type_name(v)),
        (Builder::Text(b), Value::Ip(v))          => append_display(b, v),   // today's helper
        (Builder::Text(b), Value::Mac(v))         => append_display(b, v),
        _ => unreachable!("builder built from the same visit that produced the value"),
    }
}

/// Schema and builders from one walk over a default flow: the values are
/// ignored, their kinds and the column metadata are what matter.
fn schema_and_builders(enriched_fields: &[String]) -> (Arc<Schema>, Vec<Builder>) {
    let mut fields = Vec::new();
    let mut builders = Vec::new();
    for (Column { name, nullable }, value) in fields::columns_with_values() {
        let (data_type, builder) = column_type(&value);
        fields.push(Field::new(name, data_type, nullable));
        builders.push(builder);
    }
    for name in enriched_fields {
        fields.push(Field::new(name, DataType::Utf8, true));
        builders.push(Builder::Text(StringBuilder::new()));
    }
    (Arc::new(Schema::new(fields)), builders)
}

impl FlowEncoder for Parquet {
    const EXTENSION: &'static str = "parquet";

    fn open(out: Box<dyn Write + Send>, enriched_fields: &[String]) -> io::Result<Self> {
        let (schema, columns) = schema_and_builders(enriched_fields);
        let props = WriterProperties::builder().set_compression(Compression::SNAPPY).build();
        let writer = ArrowWriter::try_new(out, Arc::clone(&schema), Some(props)).map_err(io::Error::other)?;
        Ok(Self { writer, schema, flow_column_count: columns.len() - enriched_fields.len(), columns, rows: 0 })
    }

    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        let mut i = 0;
        fields::visit(flow, |_, value| {
            append(&mut self.columns[i], value);
            i += 1;
            Ok::<(), Infallible>(())
        }).unwrap();
        for (col, value) in self.columns[self.flow_column_count..].iter_mut().zip(enriched.iter()) {
            let Builder::Text(b) = col else { unreachable!("enrichment columns are text") };
            b.append_option(value);
        }
        self.rows += 1;
        if self.rows >= BATCH_ROWS { self.flush_batch()?; }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }   // row groups flush themselves

    fn finish(mut self) -> io::Result<()> {
        self.flush_batch()?;
        self.writer.close().map(drop).map_err(io::Error::other)
    }
}
```

### 4.4 Protobuf

Step one is a pure move: `proto.rs` becomes `sink/protobuf.rs`, and
`encode` = `from_flow` + `encode_length_delimited` into a reused `Vec<u8>`.
Step two (section 9.2) removes the per-flow allocations.

### 4.5 Discard

```rust
pub struct Discard;
impl FlowEncoder for Discard {
    const EXTENSION: &'static str = "discard";
    fn open(_: Box<dyn Write + Send>, _: &[String]) -> io::Result<Self> { Ok(Self) }
    fn encode(&mut self, _: &CommonFlow, _: &Enriched) -> io::Result<()> { Ok(()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
    fn finish(self) -> io::Result<()> { Ok(()) }
}

/// `--format raw --serialization discard` is allowed today and stays allowed.
impl RawEncoder for Discard {
    fn write_value<T: Serialize>(&mut self, _: &T) -> io::Result<()> { Ok(()) }
}
```

That replaces both the `WriterKind::Discard` variant and the
`if self.serialization == Discard { return }` check at the top of every
write method. `build()` pairs `Discard` with `Destination::Null`, so no file
is ever opened for it.

---

## 5. Layer 2: `Destination`

A pure move of what exists, with a narrower interface. Everything about
paths, temp names, and renames lives here and nowhere else.

```rust
// sink/destination.rs
pub enum Destination {
    Stdout,
    File(PathBuf),
    Partitioned { root: PathBuf, level: u8, prefix: String, interval_secs: i64 },
    Null,                                  // Discard
}

/// What `open_for` hands back: where to write, how to commit, when to rotate.
pub struct Opened {
    pub writer: Box<dyn Write + Send>,
    pub pending: Option<PendingRename>,
    /// Unix timestamp of the next rotation; `None` = never.
    pub rotate_at: Option<i64>,
}

/// A file being written under a temporary name. Nothing else knows the
/// naming scheme.
#[must_use = "a pending rename that is dropped leaves a .tmp file behind"]
pub struct PendingRename { tmp: PathBuf, final_path: PathBuf }

impl PendingRename {
    pub fn commit(self) -> io::Result<()> {
        std::fs::rename(&self.tmp, &self.final_path)
    }
}

impl Destination {
    pub fn open_for(&self, now: DateTime<Utc>, extension: &str) -> io::Result<Opened> {
        match self {
            Self::Stdout => Ok(Opened { writer: Box::new(io::stdout()), pending: None, rotate_at: None }),
            Self::Null   => Ok(Opened { writer: Box::new(io::sink()),   pending: None, rotate_at: None }),
            Self::File(path) => Ok(Opened { writer: Box::new(create(path)?), pending: None, rotate_at: None }),
            Self::Partitioned { root, level, prefix, interval_secs } => {
                let window_start = now.timestamp().div_euclid(*interval_secs) * *interval_secs;
                let stamp = DateTime::from_timestamp(window_start, 0).unwrap_or(now);
                let final_path = partition_path(root, *level, prefix, extension, stamp);
                let tmp = temp_path(&final_path);
                Ok(Opened {
                    writer: Box::new(create(&tmp)?),
                    pending: Some(PendingRename { tmp, final_path }),
                    rotate_at: Some(window_start + interval_secs),
                })
            }
        }
    }
}

fn create(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    OpenOptions::new().create(true).write(true).truncate(true).open(path)
}
```

`partition_path`, `temp_path`, `MAX_PARTITION_LEVEL`, `LEVEL_3_MINUTES` and
all nine `partition_*` tests move here verbatim.

---

## 6. Layer 3: `RotatingSink<E>` and the `FlowSink` trait

The two values of `--format` differ only in the encoder layer. Everything
below it is shared:

| | `--format common` | `--format raw` |
| --- | --- | --- |
| Record | `CommonFlow` plus `Enriched` | a decoded packet, any `Serialize` type |
| Encoder trait | `FlowEncoder` (section 4) | `RawEncoder` (section 4.1) |
| Encoders allowed | ndjson, csv, parquet, protobuf, discard | ndjson, discard |
| Sink type | `Box<dyn FlowSink>` from `build()` (6.2) | `RawSink` enum from `build_raw()` (6.1) |
| Where it runs | encoder thread (section 8) | ingest thread, same `FlushTimer` (6.1) |
| Shared | `Destination`, `RotatingSink<E>`, `PendingRename`, `SinkErrors`, output metrics | |


```rust
// sink/mod.rs
pub trait FlowSink: Send {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;
    /// Close the current window and open the next if `now` is past the
    /// rotation boundary. Cheap when it is not.
    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool>;
    /// Push buffered bytes out. Called on the encoder loop's idle tick.
    fn flush(&mut self) -> io::Result<()>;
    fn finish(self: Box<Self>) -> io::Result<()>;
}
```

```rust
// sink/rotating.rs
pub struct RotatingSink<E: FlowEncoder> {
    destination: Destination,
    enriched_fields: Vec<String>,
    current: Window<E>,
    dirty: bool,
}

struct Window<E> {
    encoder: E,
    pending: Option<PendingRename>,
    rotate_at: Option<i64>,
}

impl<E: FlowEncoder> Window<E> {
    fn open(destination: &Destination, fields: &[String], now: DateTime<Utc>) -> io::Result<Self> {
        let Opened { writer, pending, rotate_at } = destination.open_for(now, E::EXTENSION)?;
        Ok(Self { encoder: E::open(writer, fields)?, pending, rotate_at })
    }

    /// Finish the stream, then (and only then) give the file its final name.
    fn close(self) -> io::Result<()> {
        self.encoder.finish()?;
        self.pending.map_or(Ok(()), PendingRename::commit)
    }
}

impl<E: FlowEncoder> RotatingSink<E> {
    pub fn open(destination: Destination, enriched_fields: Vec<String>) -> io::Result<Self> {
        let current = Window::open(&destination, &enriched_fields, Utc::now())?;
        Ok(Self { destination, enriched_fields, current, dirty: false })
    }
}

impl<E: FlowEncoder> FlowSink for RotatingSink<E> {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.current.encoder.encode(flow, enriched)?;
        self.dirty = true;
        Ok(())
    }

    /// `Ok(false)` when nothing was due. Callers must not treat that as a
    /// successful rotation (section 10).
    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> {
        let Some(rotate_at) = self.current.rotate_at else { return Ok(false) };
        if now.timestamp() < rotate_at { return Ok(false); }

        match Window::open(&self.destination, &self.enriched_fields, now) {
            Ok(next) => {
                let previous = std::mem::replace(&mut self.current, next);
                self.dirty = false;
                previous.close()?;        // finish + rename; error propagates, next window is already live
                Ok(true)
            }
            Err(e) => {
                // Keep writing to the current file; try again next window.
                if let Destination::Partitioned { interval_secs, .. } = self.destination {
                    self.current.rotate_at = Some(rotate_at + interval_secs);
                }
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.dirty { return Ok(()); }
        self.current.encoder.flush()?;
        self.dirty = false;
        Ok(())
    }

    fn finish(self: Box<Self>) -> io::Result<()> {
        self.current.close()
    }
}

/// Raw mode: available only where the encoder implements `RawEncoder`.
impl<E: RawEncoder> RotatingSink<E> {
    pub fn write_raw<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        self.current.encoder.write_value(value)?;
        self.dirty = true;
        Ok(())
    }
}
```

No `Mutex`, no `Arc`, no `Weak`, no `impl Drop`. The `Option<ArrowWriter>`
and the "write after finish" runtime check are gone because `close(self)`
consumes the window.

### 6.1 The raw sink

`write_raw` is generic over `T: Serialize`, so it cannot go behind
`dyn`. Raw mode has exactly two legal encoders, so a two-variant enum is
the honest representation; a third variant cannot be added without a
`RawEncoder` impl, which is the invariant `validate_cli` enforces by hand
today.

```rust
// sink/mod.rs
pub enum RawSink {
    Ndjson(RotatingSink<Ndjson>),
    Discard(RotatingSink<Discard>),
}

impl RawSink {
    pub fn write<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        match self { Self::Ndjson(s) => s.write_raw(value), Self::Discard(s) => s.write_raw(value) }
    }
    pub fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> { /* same match */ }
    pub fn flush(&mut self) -> io::Result<()> { /* same match */ }
    pub fn finish(self) -> io::Result<()> { /* same match */ }
}
```

Raw mode runs on the ingest thread and today relies on the shared flusher
thread for its periodic flush. After that thread is gone, the ingest loop
drives the same lifecycle itself with the `FlushTimer` from section 8. The
socket read timeout (`CHUNK_FLUSH_TIMEOUT`, 100 ms) already wakes the loop
often enough:

```rust
// lib.rs, raw socket path (netflow shown; sflow is identical)
let mut timer = FlushTimer::new(FLUSH_INTERVAL);
let mut gate = SinkErrors::new(&metrics);
while !SHUTDOWN.load(Ordering::Relaxed) {
    match reader.read_raw() {
        Ok(NetflowReadResult::Packet { packet, .. }) => {
            gate.write(sink.write(&packet));
        }
        Ok(NetflowReadResult::Timeout) => {}
        // … parse errors / metrics unchanged …
    }
    if timer.due() {
        let now = Utc::now();
        gate.rotate(sink.rotate_if_due(now));
        gate.flush(sink.flush());
    }
}
if let Err(e) = sink.finish() { eprintln!("Failed to finalize output: {e}"); }
```

Raw pcap mode needs no timer: it writes until the file is exhausted and
calls `finish` once.

### 6.2 The one and only match on the format

```rust
// sink/mod.rs
pub fn build(cli: &SinkConfig, enriched_fields: Vec<String>) -> io::Result<Box<dyn FlowSink>> {
    let dest = cli.destination();       // the (path, interval) -> Destination logic from OutputWriter::new
    Ok(match cli.serialization {
        SerializationFormat::Ndjson   => Box::new(RotatingSink::<Ndjson>::open(dest, enriched_fields)?),
        SerializationFormat::Csv      => Box::new(RotatingSink::<Csv>::open(dest, enriched_fields)?),
        SerializationFormat::Parquet  => Box::new(RotatingSink::<Parquet>::open(dest, enriched_fields)?),
        SerializationFormat::Protobuf => Box::new(RotatingSink::<Protobuf>::open(dest, enriched_fields)?),
        SerializationFormat::Discard  => Box::new(RotatingSink::<Discard>::open(Destination::Null, enriched_fields)?),
    })
}

/// `--format raw`. The error replaces `validate_cli`'s hand-written check.
pub fn build_raw(cli: &SinkConfig) -> io::Result<RawSink> {
    let dest = cli.destination();
    Ok(match cli.serialization {
        SerializationFormat::Ndjson  => RawSink::Ndjson(RotatingSink::open(dest, Vec::new())?),
        SerializationFormat::Discard => RawSink::Discard(RotatingSink::open(Destination::Null, Vec::new())?),
        other => return Err(io::Error::other(format!(
            "--serialization {other} requires --format common"
        ))),
    })
}
```

Each `RotatingSink<E>` is monomorphized; the single `dyn` dispatch happens
once per flow at the `FlowSink` boundary, which is cheaper than the
`Mutex` lock it replaces.

`run()` matches on `cli.format` once, builds either a `Box<dyn FlowSink>`
or a `RawSink`, and hands it to the matching pipeline. The `unreachable!`
in today's `write_raw` no longer exists because the raw pipeline's
parameter type cannot hold a CSV or Parquet encoder.

---

## 7. One field list: `fields.rs`

Replace the five parallel lists with one walk over a destructured
`CommonFlow`. The destructure has **no `..`**, so adding a field in
`rustflow_core` fails to compile here until every sink handles it.

The boundary is deliberately narrow. This module states three facts about
a flow and nothing about any format:

- the column names, in order
- the typed value of each column
- whether the column can be null, which is a property of the struct

How a `u16` or an `IpAddr` is written is the encoder's decision, made in
the encoder's own file (sections 4.2 and 4.3). `fields.rs` imports neither
`csv` nor `arrow`.

```rust
// sink/fields.rs
use std::net::IpAddr;
use macaddr::MacAddr6;
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

/// Column metadata. `nullable` is decided by whether the struct field is an
/// `Option`, not by any output format.
#[derive(Clone, Copy)]
pub struct Column {
    pub name: &'static str,
    pub nullable: bool,
}

/// The typed value of one column. Each variant is a kind an encoder must
/// know how to write; the `Option` inside carries presence.
#[derive(Clone, Copy)]
pub enum Value {
    FlowType(FlowType),
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
    /// Nanoseconds since the Unix epoch. Kept distinct from `U64` so a
    /// columnar format can type it as a timestamp.
    TimestampNs(Option<i64>),
    Ip(Option<IpAddr>),
    Mac(Option<MacAddr6>),
}

const REQUIRED: bool = false;
const OPTIONAL: bool = true;

/// Walk every column of a flow, in output order.
pub fn visit<E>(
    flow: &CommonFlow,
    mut f: impl FnMut(Column, Value) -> Result<(), E>,
) -> Result<(), E> {
    let CommonFlow {
        flow_type, time_received_ns, sequence_num, sampling_rate, sampler_address,
        time_flow_start_ns, time_flow_end_ns, bytes, packets, src_addr, dst_addr,
        src_mac, dst_mac, etype, proto, src_port, dst_port, in_if, out_if, ip_tos,
        ip_ttl, tcp_flags, icmp_type, icmp_code, ipv6_flow_label, fragment_id,
        fragment_offset, src_as, dst_as, next_hop, src_net, dst_net, bgp_next_hop,
        src_vlan, dst_vlan, observation_domain_id, template_id,
    } = flow;                                   // <- no `..`: new fields break the build here

    let mut col = |name, nullable, value| f(Column { name, nullable }, value);

    col("flow_type",          REQUIRED, Value::FlowType(*flow_type))?;
    col("time_received_ns",   OPTIONAL, Value::TimestampNs(*time_received_ns))?;
    col("sequence_num",       REQUIRED, Value::U32(Some(*sequence_num)))?;
    col("sampling_rate",      OPTIONAL, Value::U32(*sampling_rate))?;
    col("sampler_address",    OPTIONAL, Value::Ip(*sampler_address))?;
    col("time_flow_start_ns", OPTIONAL, Value::TimestampNs(*time_flow_start_ns))?;
    col("time_flow_end_ns",   OPTIONAL, Value::TimestampNs(*time_flow_end_ns))?;
    col("bytes",              REQUIRED, Value::U64(Some(*bytes)))?;
    col("packets",            REQUIRED, Value::U64(Some(*packets)))?;
    col("src_addr",           OPTIONAL, Value::Ip(*src_addr))?;
    col("dst_addr",           OPTIONAL, Value::Ip(*dst_addr))?;
    col("src_mac",            OPTIONAL, Value::Mac(*src_mac))?;
    col("dst_mac",            OPTIONAL, Value::Mac(*dst_mac))?;
    col("etype",              OPTIONAL, Value::U16(*etype))?;
    col("proto",              OPTIONAL, Value::U8(*proto))?;
    // … one line per remaining field, in today's COMMON_FLOW_HEADERS order …
    col("template_id",        OPTIONAL, Value::U16(*template_id))
}

/// Column metadata alone, e.g. for a CSV header.
pub fn columns() -> impl Iterator<Item = Column> {
    columns_with_values().map(|(c, _)| c)
}

/// Column metadata plus a value of the right kind, taken from a default
/// flow. The values are placeholders; encoders use them to pick a column
/// type at `open` time (section 4.3).
pub fn columns_with_values() -> impl Iterator<Item = (Column, Value)> {
    let mut out = Vec::with_capacity(40);
    let Ok(()) = visit(&CommonFlow::new(FlowType::Ipfix), |c, v| {
        out.push((c, v));
        Ok::<(), std::convert::Infallible>(())
    });
    out.into_iter()
}
```

There is no separate `NAMES` constant: the header, the schema, and the row
all come from the same `visit`, so nothing can drift. The one test worth
adding pins the order against today's output: assert
`columns().map(|c| c.name)` equals the current `COMMON_FLOW_HEADERS`
literal, copied into the test.

Consumers of the list:

| Consumer | How | Replaces |
| --- | --- | --- |
| CSV header | `columns()` | `COMMON_FLOW_HEADERS` |
| CSV row | `visit` + the CSV `write_text` match (section 4.2) | the 37-line `put!` block |
| Arrow schema + builders | `columns_with_values()` + the Parquet `column_type` match (section 4.3) | `build_schema` and `FlowBuilders` (3 lists, ~150 lines) |
| Parquet row | `visit` + the Parquet `append` match | `ParquetSink::write` body |
| Protobuf | keeps an explicit mapping (tags are a wire contract) but uses the same no-`..` destructure | `from_flow` |
| NDJSON | unchanged, serde is already this pattern | |

Cost: one `match` on `Value` per column per flow in CSV and Parquet, in
place of a direct typed call. That is noise next to formatting or an Arrow
append, and the golden tests from step 0 will show if it is not.

The existing `writes_addresses_as_text` test pins the Parquet output.

---

### 7.1 Revised: the list is a macro, consumers expand it (2026-09-08)

The typed Parquet builders and the hand-written protobuf encoder each
re-listed the 37 fields, so the "one list" promise was broken three ways.
Fixed by making the list data instead of a function:

```rust
// fields.rs: the only place the fields are named
macro_rules! for_each_flow_field {
    ($callback:ident) => {
        $callback! {
            flow_type: FlowType required,
            time_received_ns: Timestamp optional,
            sequence_num: U32 required,
            // … 37 lines …
        }
    };
}
pub(crate) use for_each_flow_field;
```

Each consumer expands it with its own callback macro, at compile time:

| consumer | callback | maps `Kind presence` to |
| --- | --- | --- |
| `fields.rs` | `define_visit!` | `Value` variants; generates today's `visit` for CSV |
| `parquet.rs` | `flow_columns!` + `column_kind!` | typed Arrow builders (`Nullable<UInt16Type>`, `Timestamp`, text) |
| `protobuf.rs` | `flow_encoder!` + `put_field!` | wire writes, tag = position (38 is the map; later fields skip it) |

Every expansion destructures `CommonFlow` with no `..`, so a new core field
fails to compile until it has a line in the list. The pin tests between the
lists are gone; the protobuf tests pin the `(name, tag)` wire contract
instead, since positional tags mean the list is append-only.

Measured after the change: identical throughput (protobuf 243 ns, parquet
490 ns on varied data with 3 fields), as expected for compile-time
expansion. Cost: three callback macros of ~30 lines and a nine-word kind
vocabulary.

---

## 8. The encoder thread owns the sink

Today: `Arc<OutputWriter>` shared by the encoder thread, the flusher thread,
and `run()`. Target: the encoder thread owns `Box<dyn FlowSink>`; the flusher
thread is folded into the receive loop with `recv_timeout`.

The flush cadence must be a **deadline**, not a receive timeout. A plain
`recv_timeout(FLUSH_INTERVAL)` restarts the clock on every chunk, so a
steady trickle of chunks every 100 ms would never time out and the buffer
would only reach the file when it fills. Today's flusher thread guarantees
a line is at most 250 ms stale; that guarantee has to survive.

```rust
// sink/mod.rs
/// A fixed-cadence deadline, shared by the encoder loop and the raw ingest
/// loop. `due()` is true once per interval regardless of how often it is
/// polled, and the next deadline is anchored to the previous one so the
/// cadence does not drift under load.
pub struct FlushTimer { next: Instant, interval: Duration }

impl FlushTimer {
    pub fn new(interval: Duration) -> Self { Self { next: Instant::now() + interval, interval } }

    pub fn remaining(&self) -> Duration { self.next.saturating_duration_since(Instant::now()) }

    pub fn due(&mut self) -> bool {
        let now = Instant::now();
        if now < self.next { return false; }
        self.next = (self.next + self.interval).max(now);   // never schedule in the past
        true
    }
}
```

```rust
// lib.rs
fn encoder_loop(
    rx: mpsc::Receiver<Vec<CommonFlow>>,
    mut sink: Box<dyn FlowSink>,
    enrichment: Arc<EnrichmentEngine>,
    metrics: Arc<Metrics>,
) {
    let mut enriched = Enriched::new(enrichment.output_fields().len());
    let mut gate = SinkErrors::new(&metrics);      // section 10
    let mut timer = FlushTimer::new(FLUSH_INTERVAL);

    loop {
        // Wait for a chunk, but never past the flush deadline.
        match rx.recv_timeout(timer.remaining()) {
            Ok(flows) => {
                // Once per chunk, not once per flow.
                gate.rotate(sink.rotate_if_due(Utc::now()));
                for flow in &flows {
                    enrichment.enrich_into(flow, &mut enriched);
                    gate.write(sink.write(flow, &enriched));
                }
                metrics.output_flows_total.inc_by(flows.len() as f64);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,     // ingest ended
        }
        // Checked after every chunk as well as on timeout, so a busy
        // pipeline flushes on cadence and an idle one still rotates its
        // empty window on time.
        if timer.due() {
            gate.rotate(sink.rotate_if_due(Utc::now()));
            gate.flush(sink.flush());
        }
    }
    if let Err(e) = sink.finish() {
        eprintln!("Failed to finalize output: {e}");
    }
}
```

A unit test for `FlushTimer` should cover the starvation case directly:
poll `due()` every 100 ms for one second and assert it returned `true`
about four times.

What this deletes from the current code:

- `spawn_flusher`, `flush_loop`, the `Weak<OutputWriter>` upgrade dance
- `Mutex<State>` and the `state.lock().unwrap()` in every method
- `impl Drop for OutputWriter` (finish is explicit and happens exactly once)
- the `output.finish()` at the end of `run()` for the pipelined paths

And it fixes a real behaviour gap: today rotation only runs when a flow
arrives, so an idle exporter leaves the previous window's `.tmp` file
unrenamed until traffic resumes. With the idle tick, windows close on time.

The pcap paths (`read_netflow_pcap`, `read_sflow_pcap`) should push through
the same `Encoder` so there is exactly one place that touches the sink.
Today they call `output.write_enriched_flow` inline on the main thread.

---

## 9. Performance

Everything above is neutral or better. These are the additional measurable
items, in order of expected payoff. Baseline every one on the bench VM with
`--serialization discard` (decode + enrich only) versus each format.

### 9.1 Per-chunk instead of per-flow (comes free with section 8)

| Per-flow today | After |
| --- | --- |
| `Mutex` lock/unlock | none |
| `Utc::now()` in `rotate_if_due` | once per chunk of 256 |
| `HashMap<String, String>` alloc + insert per enrichment field | reused `Enriched` slots |
| `enriched.get(name)` hash per field per encoder | index |

### 9.2 Protobuf: encode straight into the buffer

`proto::CommonFlow::from_flow` allocates per flow: up to 6 `Vec<u8>` for
addresses/MACs, one `String` for `flow_type`, and a full `HashMap` clone for
`enriched`. The wire schema is fixed, so encode by hand with `prost::encoding`
and keep the derived struct only as the test oracle.

Two rules keep the hand encoder faithful to what prost emits today:

1. **Non-optional scalars are omitted when they hold the proto3 default.**
   `prost-derive` wraps every plain scalar in `if value != default`, so a
   flow with `sequence_num == 0`, `bytes == 0`, or `packets == 0` has no
   tag 3 / 8 / 9 on the wire. `flow_type` (tag 1) is never empty. Optional
   fields are emitted whenever `Some`, including `Some(0)`.
2. **Map entries are emitted in `output_fields` order.** prost iterates the
   `HashMap`, so today's order is random per process. Positional order is
   a determinism improvement, and it is why the guarantee for enriched
   protobuf output is "identical decoded message", not "identical bytes".

```rust
// sink/protobuf.rs
use prost::encoding::{encode_key, encode_varint, encoded_len_varint, key_len, WireType};

pub struct Protobuf {
    out: BufWriter<Box<dyn Write + Send>>,
    names: Vec<String>,
    body: Vec<u8>,          // reused; one message
}

fn put_bytes(tag: u32, bytes: &[u8], buf: &mut Vec<u8>) {
    encode_key(tag, WireType::LengthDelimited, buf);
    encode_varint(bytes.len() as u64, buf);
    buf.extend_from_slice(bytes);
}
fn put_u32(tag: u32, v: u32, buf: &mut Vec<u8>) {
    encode_key(tag, WireType::Varint, buf);
    encode_varint(u64::from(v), buf);
}
/// A non-optional proto3 scalar: absent on the wire when it is the default.
fn put_u64_nondefault(tag: u32, v: u64, buf: &mut Vec<u8>) {
    if v != 0 { encode_key(tag, WireType::Varint, buf); encode_varint(v, buf); }
}
fn put_ip(tag: u32, addr: IpAddr, buf: &mut Vec<u8>) {
    match addr {
        IpAddr::V4(a) => put_bytes(tag, &a.octets(), buf),
        IpAddr::V6(a) => put_bytes(tag, &a.octets(), buf),
    }
}
fn bytes_field_len(tag: u32, len: usize) -> usize {
    key_len(tag) + encoded_len_varint(len as u64) + len
}

impl Protobuf {
    fn encode_body(&mut self, flow: &CommonFlow, enriched: &Enriched) {
        let b = &mut self.body;
        b.clear();
        put_bytes(1, flow_type_name(flow.flow_type).as_bytes(), b);
        if let Some(v) = flow.time_received_ns { encode_key(2, WireType::Varint, b); encode_varint(v as u64, b); }
        put_u64_nondefault(3, u64::from(flow.sequence_num), b);     // rule 1
        if let Some(v) = flow.sampling_rate   { put_u32(4, v, b); }
        if let Some(a) = flow.sampler_address { put_ip(5, a, b); }
        // … tags 6, 7 optional …
        put_u64_nondefault(8, flow.bytes, b);                       // rule 1
        put_u64_nondefault(9, flow.packets, b);                     // rule 1
        // … tags 10–37 optional, exactly as in proto/rustflow.proto …

        // map<string,string> enriched = 38: one length-delimited entry per present value
        for (name, value) in self.names.iter().zip(enriched.iter()) {
            let Some(value) = value else { continue };
            let entry_len = bytes_field_len(1, name.len()) + bytes_field_len(2, value.len());
            encode_key(38, WireType::LengthDelimited, b);
            encode_varint(entry_len as u64, b);
            put_bytes(1, name.as_bytes(), b);
            put_bytes(2, value.as_bytes(), b);
        }
    }
}

impl FlowEncoder for Protobuf {
    const EXTENSION: &'static str = "pb";
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.encode_body(flow, enriched);
        // length-delimited framing, same as encode_length_delimited
        let mut len = [0u8; 10];
        let mut cursor = &mut len[..];
        encode_varint(self.body.len() as u64, &mut cursor);   // Vec<u8> and &mut [u8] both impl BufMut
        let n = 10 - cursor.len();
        self.out.write_all(&len[..n])?;
        self.out.write_all(&self.body)
    }
    // open / flush / finish as Ndjson
}

fn flow_type_name(t: FlowType) -> &'static str {
    match t { FlowType::NetflowV5 => "NETFLOW_V5", FlowType::NetflowV9 => "NETFLOW_V9",
              FlowType::Ipfix => "IPFIX", FlowType::SflowV5 => "SFLOW_V5" }
}
```

Tests, matching the guarantee table at the top:

- **Byte equality without enrichment.** For a set of flows including one
  with all-zero counters and one with every optional field set, assert
  `hand_encode(flow) == from_flow(flow, &{}).encode_length_delimited()`.
  prost's output is deterministic when the map is empty, so this is exact.
- **Semantic equality with enrichment.** Decode the hand-encoded bytes with
  the derived `proto::CommonFlow` and assert it equals `from_flow(flow,
  enriched)`. `PartialEq` on the derived struct compares the map by
  content, so order is irrelevant here, as it must be.
- **Determinism.** Encode the same enriched flow twice and assert the bytes
  are identical (this is the property today's encoder lacks).

Zero allocations per flow after warm-up.

### 9.3 CSV: one copy fewer per field

Today's `write_csv_record` already reuses its `Vec<String>` and each
`String`'s allocation, so there are no per-flow allocations to remove.
What section 4.2 removes is one copy per field: today each value is
formatted into a `String` and then copied by the csv crate into its own
buffer; with `write_field` the value goes from the scratch buffer straight
into the csv buffer. That is a modest win and may not show on the bench.
If the csv crate's per-field quoting check is what shows instead, the
numeric and address columns can bypass it (they can never need quoting)
and only enrichment strings go through `csv_core`. Do either only if
measured.

### 9.4 NDJSON

Already streams. The only change is `flatten` (section 4.1), which is a
cleanliness win; verify it is not a perf loss, and keep the splice if it is.

### 9.5 Parquet

Unchanged algorithmically. Two knobs worth trying on the VM, separately:

- `WriterProperties::set_max_row_group_size` aligned with `BATCH_ROWS` so a
  batch is exactly one row group (memory bound = one batch of builders).
- `set_dictionary_enabled` is on by default and is right for `flow_type`,
  `proto`, and addresses; confirm it is not hurting the high-cardinality
  timestamp columns (`set_column_dictionary_enabled(path, false)`).

---

## 10. Errors and metrics

Every write returns `io::Result`. Policy lives in one place, the encoder
loop, through a gate that logs on state change instead of per record.

Each operation gets its **own** gate. A single shared gate would let a
no-op `rotate_if_due` (`Ok(false)`, nothing was due) clear a write failure,
and a persistent write failure would then log "recovered" / "failed" on
every chunk. Recovery is only reported when the *same* operation that
failed succeeds again, and a rotation that was not attempted is not an
observation at all.

```rust
struct ErrorGate { what: &'static str, failing: bool }

impl ErrorGate {
    /// Record one attempted operation. `Ok` after `Err` logs a recovery;
    /// repeated `Err` only counts.
    fn observe(&mut self, result: io::Result<()>, counter: &prometheus::Counter) {
        match (result, self.failing) {
            (Ok(()), true)  => { eprintln!("{} recovered", self.what); self.failing = false; }
            (Ok(()), false) => {}
            (Err(e), false) => { eprintln!("{} failed: {e}", self.what); self.failing = true; counter.inc(); }
            (Err(_), true)  => { counter.inc(); }
        }
    }
}

/// One gate per operation, so they cannot mask each other.
pub struct SinkErrors<'m> {
    write: ErrorGate,
    rotate: ErrorGate,
    flush: ErrorGate,
    metrics: &'m Metrics,
}

impl SinkErrors<'_> {
    pub fn write(&mut self, r: io::Result<()>) {
        self.write.observe(r, &self.metrics.output_write_errors_total);
    }
    pub fn flush(&mut self, r: io::Result<()>) {
        self.flush.observe(r, &self.metrics.output_write_errors_total);
    }
    /// `Ok(false)` means no rotation was due: not a success, not observed.
    pub fn rotate(&mut self, r: io::Result<bool>) {
        match r {
            Ok(false) => {}
            Ok(true)  => self.rotate.observe(Ok(()), &self.metrics.output_rotate_errors_total),
            Err(e)    => self.rotate.observe(Err(e), &self.metrics.output_rotate_errors_total),
        }
    }
}
```

Unit test: feed `write(Err)`, then `rotate(Ok(false))` many times, then
`write(Err)`; assert exactly one "failed" line and no "recovered" line.

New metrics in `metrics.rs`, all plain counters:

| Metric | Incremented where |
| --- | --- |
| `output_flows_total` | encoder loop, per chunk |
| `output_bytes_total` | a `CountingWriter<W: Write>` wrapped around the `Box<dyn Write>` in `Destination::open_for` |
| `output_files_total` | `Window::open` |
| `output_write_errors_total` | `SinkErrors::write` and `::flush` |
| `output_rotate_errors_total` | `SinkErrors::rotate` |

`CountingWriter` is ten lines: `impl Write` that forwards and adds `n` to a
shared counter.

---

## 11. Migration order

Each step compiles, keeps `cargo test -p rustflow_collect` green, and keeps
the golden tests from step 0 green. Commit after each.

0. **Golden output tests, before anything moves.** The existing e2e tests
   only parse NDJSON from stdout, so the multi-format guard has to be
   built first. Extend `tests/` with one test per format that runs
   `rustflow collect --pcap … -o <tmp>` on the checked-in pcaps and
   compares against files captured from the current binary and committed
   under `tests/golden/`:

   | Format | Comparison | Cases |
   | --- | --- | --- |
   | NDJSON | bytes | common, raw; with and without `--enrich` |
   | CSV | bytes | with and without `--enrich` |
   | Protobuf | bytes | without `--enrich` |
   | Protobuf | decoded messages (`protobuf` package, compare as dicts) | with `--enrich` |
   | Parquet | `pyarrow` schema + `to_pylist()` | with and without `--enrich` |
   | Any | file names under the tree | `--interval 1h --level 3` on a pcap spanning two windows |

   Pcap mode stamps `time_received_ns` from the capture timestamps, so
   every run is deterministic. `--enrich` cases use a small CSV prefix
   table committed next to the goldens. `--format raw --serialization
   discard` gets a test that asserts it still runs and writes nothing.

1. **`Enriched`** (section 3). Change `EnrichmentEngine::enrich` to
   `enrich_into`, change the four `write_*` call sites. Pure plumbing; the
   encoders still do `enriched.get(i)` where they did `.get(name)`.
   *Skip or adapt if the enrich rewrite already did this.*
2. **`sink/destination.rs`** (section 5). Move `Destination`, `partition_path`,
   `temp_path`, `commit_file`, the nine `partition_*` tests. `create_writer`
   becomes `Destination::open_for` + a match on the format. No behaviour change.
3. **`FlowEncoder` + one file per format** (section 4). `WriterKind` becomes
   five structs. `flush`/`finish`/`write_enriched_flow` matches disappear.
   Move `parquet_sink.rs` and `proto.rs` under `sink/`. Existing encoder tests
   move with them.
4. **`RotatingSink<E>` + `FlowSink` + `RawSink` + `build()`** (section 6).
   `OutputWriter` is deleted. `run()` calls `sink::build` or
   `sink::build_raw`. Raw paths take `RawSink` by type; `write_raw`'s
   `unreachable!` is gone and `--format raw --serialization discard` still
   works.
5. **Loops own their sinks** (sections 8 and 6.1). `FlushTimer` in both the
   encoder loop and the raw ingest loops; delete the flusher thread,
   `Mutex`, `Arc`, `Weak`, `Drop`. Route common-format pcap mode through
   `Encoder` too.
6. **`fields.rs`** (section 7). Replace the five field lists. Add the
   column-order test against today's header literal.
7. **Errors + metrics** (section 10).
8. **Protobuf hand encoding** (section 9.2), then CSV/Parquet knobs (9.3,
   9.5), each behind a before/after bench run.

Steps 1–5 are structural and should not move the benchmark. Step 6 is
neutral. Steps 7–8 are where the numbers change; measure each alone.

---

## 12. Verification

- `cargo test -p rustflow_collect` after every step. New unit tests called
  out above: `FlushTimer` cadence under a steady trickle (section 8),
  `SinkErrors` not reporting recovery on a no-op rotation (section 10),
  protobuf byte / semantic / determinism (section 9.2), and
  the `fields::columns()` order matching today's header (section 7).
- The step 0 golden tests after every step. Step 8 (hand-written protobuf)
  is the only step expected to change any golden, and only the enriched
  protobuf case, whose comparison is already semantic.
- Bench VM: the usual generator run for each serialization with
  `--serialization discard` as the baseline. Record decode-only, then each
  format, before step 1 and after steps 5, 7, 8.
- Manual, flush cadence: run against a generator sending a small steady
  rate (a few packets per 100 ms) to a file, and `tail -f` it. Lines must
  appear within the flush interval, not only when the buffer fills.
- Manual, rotation: run with `--interval 1m --output out/` against an
  exporter, stop traffic for two minutes, confirm the idle window's file is
  renamed from `.tmp` on time (this is the behaviour section 8 fixes).

---

## 13. Forward-looking: multiple ingest workers (`SO_REUSEPORT`)

Not part of this work, but the design should not get in its way. It does
not, and two small choices in step 5 keep it that way.

**Why it already fits.** N reuseport sockets means N ingest threads, each
decoding into chunks. The sink is owned by one encoder thread fed by a
channel, and `mpsc::SyncSender` is `Clone`, so N producers into one
consumer needs no sink change. The single-owner sink is what makes this
cheap: today's `Mutex<State>` would be contended by every worker on every
flow.

```
   ingest w0 ─┐
   ingest w1 ─┼─ SyncSender clones ──> encoder thread ──owns──> Box<dyn FlowSink>
   ingest w2 ─┘
```

**Where it bottlenecks.** Workers help until the single encoder saturates,
which for NDJSON is roughly when encode cost equals decode cost. Two ways
out; the design supports the first with no trait change:

| | N encoders, N sinks, N files | N encoders, one writer |
| --- | --- | --- |
| How | one `RotatingSink` per worker; worker id in the file name (`flows-w2-<stamp>.parquet`) | encoders emit bytes / `RecordBatch`, one thread writes |
| Sink change | `Destination::Partitioned` gains an optional worker suffix | `FlowEncoder::encode` split from the write |
| Parquet | one file per worker; readers glob the directory | one file, batches handed over a channel |
| Limits | needs directory output; stdout and single file keep one encoder | only needed for single-file + parallel encode |
| Prepare now? | no; the change is local to `Destination` | no |

**Prepare now (both zero-cost, done in step 5):**

1. Split today's `Encoder` struct into a per-producer `FlowBatcher`
   (a `SyncSender` clone plus its chunk buffer, `push` / `flush`) and one
   `EncoderThread` (the join handle, `drain`). Shutdown: each worker drops
   its batcher, the channel closes when the last sender is gone, the
   encoder drains and finishes exactly as today.
2. `FlowSink: Send`, never `Sync`. Nothing needs `Sync`; needing it later
   would mean a sink is being shared again.

**Not sink concerns, noted for completeness.** Per-exporter ordering and
NetFlow v9 / IPFIX template state live in the ingest workers. Linux hashes
reuseport by source address and port, so one exporter stays on one worker
and its templates stay in that worker's parser. macOS does not load balance
reuseport the same way; treat this as a Linux feature.

---

## 14. Measured: encoder throughput and hot paths (2026-09-07, Apple M1, single thread)

`cargo bench -p rustflow_sink`, one fully populated flow repeated, three
enrichment fields, output to a byte-counting null writer. Profiles from
`sample` on a 12 s single-encoder run (`BENCH_ENCODER=<name> BENCH_SECS=12`,
built with `CARGO_PROFILE_BENCH_DEBUG=1`).

| encoder | flows/s | ns/flow | share of samples | where |
| --- | ---: | ---: | ---: | --- |
| ndjson | 1.28 M | 780 | 38 % | `serialize_str`: escaping scan of ~40 keys + ~9 string values per line |
| | | | 30 % | `memmove`: ~6 tiny `BufWriter` writes per field (quote, key, quote, colon, value, comma) |
| | | | 22 % | serde `flatten` / `serialize_entry` glue |
| | | | 11 % | `core::fmt`: IPv6 `Display` (`LowerHex` per segment) via serde's stack buffer |
| csv | 0.81 M | 1240 | 44 % | `core::fmt`: `write!("{v}")` for ~30 integers goes through `fmt::write` → `pad_integral`; MAC is six `{:02X}` calls |
| | | | 18 % | `csv_core`: quoting scan of every field + `write_delimiter` |
| | | | 18 % | `memmove`: scratch → csv buffer → writer, two copies per field |
| | | | 20 % | `Value` match + scratch bookkeeping |
| protobuf | 1.33 M | 750 | 42 % | `malloc`/`free`: `from_flow` makes ~15 allocations per flow (5 IP + 2 MAC `Vec`s, `flow_type` `String`, `HashMap` + 6 `String`s); macOS malloc alone spends 10 % in `mach_absolute_time` |
| | | | 33 % | building `FlowMessage` + prost `encoded_len` (computed for framing, again per map entry) |
| | | | 12 % | `encode_varint`, inherent |
| parquet | 0.99 M | 1010 | 34 % | `core::fmt`: 8 text columns (5 IPs, 2 MACs, flow_type) formatted into `StringBuilder` |
| | | | 27 % | parquet column writer: `write_mini_batch`, RLE, data pages; amortized per 32 768-row batch |
| | | | 12 % | dictionary encoding of the text columns: `ahash` + `memcmp` in the interner per value |
| | | | 11 % | `Value` match + `append` |
| | | | 3 % | arrow builders |

**Cross-cutting.** Formatting IP and MAC addresses through `core::fmt` is
the one cost shared by NDJSON, CSV, and Parquet. serde already avoids it
for IPv4 (a fixed 15-byte stack buffer), but IPv6 and MAC go through the
generic formatter everywhere. One `fmt_ip` / `fmt_mac` helper writing
digits into a byte buffer pays off in all three encoders.

**Per encoder, in order of payoff (estimates, to be measured):**

| encoder | change | expected ns/flow |
| --- | --- | ---: |
| protobuf | hand encoder (section 9.2): no `FlowMessage`, no map `HashMap`, one `encoded_len` | 750 → ~300 |
| csv | `itoa` for integers, address helper, bypass `csv_core` for columns that cannot need quoting (numbers, addresses); only enrichment strings go through the quoting scan | 1240 → ~500 |
| ndjson | hand-written row writer: pre-escaped `"key":` literals (keys are static and safe), one `write_all` per field, `itoa` for numbers; keep serde for raw mode | 780 → ~400 |
| parquet | address helper (kills most of the 34 %); optionally `set_column_dictionary_enabled(false)` for the address columns to skip interning at the price of larger files; storing addresses as `FixedSizeBinary(16)` would remove both costs but changes the schema readers see | 1010 → ~700 |

**Done: address text helper (`text.rs`, same day).** `AddrText` writes
IPv4, IPv6 and MAC into a stack buffer with no `core::fmt`, byte-identical
to `Display` (pinned by edge-case tests and a 10 000-address comparison).
CSV and Parquet use it; NDJSON cannot until it has its own row writer,
because serde owns how `IpAddr` is serialized inside `CommonFlow`.

| encoder (3 fields) | before ns/flow | after ns/flow | flows/s |
| --- | ---: | ---: | ---: |
| csv | 1240 | 857 | 0.81 M → 1.17 M |
| parquet | 1008 | 628 | 0.99 M → 1.59 M |
| ndjson | 780 | 771 | unchanged, as expected |
| protobuf | 750 | 740 | unchanged, as expected |

**Done: hand-written protobuf encoder and `itoa` for CSV (same day).**
`protobuf.rs` encodes straight into a reused buffer with `prost::encoding`
helpers; the derived message is kept under `#[cfg(test)]` as the oracle,
and byte equality is pinned on a zero flow, a fully populated flow, a
`Some(0)`-heavy flow, an empty map value, and a 300-byte value (two-byte
length prefix). CSV integers go through `itoa`.

| encoder (3 fields) | start ns/flow | after addresses | after this step | flows/s now |
| --- | ---: | ---: | ---: | ---: |
| protobuf | 750 | 740 | 244 | 4.1 M |
| csv | 1240 | 857 | 661 | 1.5 M |
| parquet | 1008 | 628 | 623 | 1.6 M |
| ndjson | 780 | 771 | 778 | 1.3 M (serde, unchanged) |

Without enrichment protobuf is at 192 ns (5.2 M flows/s). The CSV
remainder is the `csv_core` quoting scan and the two copies per field;
bypassing `csv_core` for the columns that cannot need quoting is the next
CSV step if it is ever needed.

**Done: Parquet, single thread (same day).** Measured on *varied* data
(a 65 536-flow pool with realistic spread, `data = varied` in the bench);
the constant-flow numbers flatter Parquet because every column compresses
to nothing. Best-of-two on one thread, 3 enrichment fields:

| step | ns/flow | bytes/flow | note |
| --- | ---: | ---: | --- |
| start (defaults: dictionary everywhere, page statistics everywhere) | 729 | 28.9 | |
| delta encoding + no dictionary on 9 high-cardinality columns, no statistics on text | 590 | 22.1 | faster *and* 24 % smaller |
| statistics only on the 3 timestamp columns | 575 | 22.0 | time-range pruning kept; min/max of ports/counters never prunes a time-ordered file |
| typed per-column builders (`flow_columns!` macro) instead of the `fields::visit` walk | 511 | 22.0 | the `Value` enum + closure cost 14 % on this encoder |

Rejected: dictionary off everywhere (fast, 3x the file), bigger/smaller
batches (no effect), page v2 alone and larger write batches (no effect),
addresses as binary columns (−26 % more, but the file must keep addresses
as strings). Multi-threaded column encoding was built and measured
(4 threads ≈ 1.7x via the parquet crate's per-column writers) and then
removed again: the improvement wanted is single-threaded, and the path
cost ~150 lines of row-group management. `parquet.rs` is ~350 lines plus
a separate test file; the remaining size is the typed column list.

Where the remaining ~510 ns goes: ~57 % inside the parquet crate's column
writer (dictionary interning of the text columns with `ahash` + `memcmp`,
RLE of dictionary indices, page assembly), ~35 % ours (builder appends,
address text), the rest copies. The Arrow layer itself (builders, arrays,
level computation) is under 5 %, so going below Arrow would not pay.

Machine drift note: absolute numbers on this laptop move ±8 % between
runs; every comparison above was taken inside one loop.

**Caveats.** Repeating one flow makes Parquet's dictionary always hit and
Snappy compress to nothing (0.1 bytes/flow), so its column-writer share is
a lower bound for real data. The NDJSON `flatten` glue is ~50 ns; the
non-enriched fast path skips it.

**Side finding, not a sink issue.** `CommonFlow` serializes `src_mac` /
`dst_mac` through `macaddr`'s derived `Serialize`, so JSON emits
`[0,17,34,51,68,85]` while CSV and Parquet emit `00:11:22:33:44:55` and
`docs/output.md` says "string". A `serialize_with` on the field in
`rustflow_core` would align them; that is outside this crate's scope.

## 15. Stepping back to plain crates (2026-09-11)

The hand-written protobuf encoder, the `itoa` integers in CSV, and the
`AddrText` address formatter were removed. They were measurably faster
(section 14) but made the encoders large and unlike the rest of the code.
`protobuf.rs` is now the prost-derived message and one
`encode_length_delimited`; CSV and the Parquet text columns format through
`Display`. `CRATE_NOTES.md` records what the profiling taught us about each
crate, the before/after numbers, and the changes that would help without
custom code. The Parquet writer settings and typed column builders stay.
