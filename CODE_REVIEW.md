# rustflow code review — 2026-09-04

Whole-workspace review of the current state of `main` (commit `d6960f1`).
Findings are ranked by severity. **Confirmed** means the reviewer verified
the failure by reading the code against the spec or by running a test.
**Plausible** means the code reading supports the claim but it was not
independently reproduced.

Nothing in the tree was modified by the review itself. Items 1.1–1.5 were
fixed afterwards (see **Status** notes); everything else is still open.

---

## 1. Critical: protocol decoding bugs that lose traffic

### 1.1 NetFlow v9 header `count` is treated as the number of FlowSets — Confirmed (empirically)

**Status: fixed 2026-09-04** (with regression tests in the parser's `tests` module).

`crates/rustflow_core/src/netflow_v9/parser.rs:51`

`NetflowV9Parser::parse` does `count(parse_flow_set, header.count)`. RFC 3954
§5.1 defines `count` as the **total number of records** (template + options +
data), not the number of FlowSets. nom's `count` is strict, so once the input
is exhausted the next `be_u16` fails and the whole packet errors.

Verified with a throwaway integration test: a packet holding one template
FlowSet and one data FlowSet with two records:

| header count | result |
|---|---|
| 3 (RFC-correct: 1 template + 2 data records) | `Err(Eof)` |
| 2 (number of FlowSets) | `Ok`, 2 FlowSets |

`NetflowProcessor::process` (`crates/rustflow/src/processor.rs:235`) swallows
the error and returns an empty Vec, so every real exporter that packs more than
one record per FlowSet loses all of its flows with no log line.

**Fix:** parse FlowSets with `many0` (or a loop until input is exhausted) and
optionally cross-check the summed record count against `header.count` for a
warning only.

### 1.2 sFlow v5 `counter_record` reads an extra length word — Confirmed

**Status: fixed 2026-09-04** (with regression tests in the parser's `tests` module).

`crates/rustflow_core/src/sflow_v5/parser.rs:438`

The sFlow v5 `counter_record` is `format` + `opaque counter_data<>`, i.e.
format, length, bytes. `parse_counter_record` calls `parse_record_header`
(format + length) and then reads a **second** `u32 data_length`, so the first
word of the counter data (for `if_counters`, the `ifIndex`) is consumed as a
length. `parse_flow_record` in the same file correctly reads only format +
length.

Example: `if_counters` record, format 1, length 88, ifIndex 1 → `data_length`
= 1, `take(1)` yields one byte, `many1(parse_if_counters)` fails, the counter
sample errors, and the entire datagram is rejected.

### 1.3 sFlow v5 `extended_gateway` layout is wrong — Confirmed

**Status: fixed 2026-09-04** (with regression tests in the parser's `tests` module).

`crates/rustflow_core/src/sflow_v5/parser.rs:801`

sFlow v5 defines:

```
struct extended_gateway {
   next_hop nexthop;          /* address type + address */
   unsigned int as;
   unsigned int src_as;
   unsigned int src_peer_as;
   as_path_type dst_as_path<>; /* array of { type, as<> } segments */
   unsigned int communities<>;
   unsigned int localpref;
}
```

`parse_extended_gateway` omits `nexthop` entirely and parses `dst_as_path` as
a single `{type, as<>}` segment instead of an array of segments. Every field is
read from the wrong offset; in practice `AsPathSegmentType::try_from` fails on
what is really the `src_as` value and the whole datagram is dropped via `data?`.

### 1.4 sFlow v5 `extended_user` skips charsets; strings ignore XDR padding — Confirmed

**Status: fixed 2026-09-04** (with regression tests in the parser's `tests` module).

`crates/rustflow_core/src/sflow_v5/parser.rs:842` and `:1247`

`extended_user` is `charset src_charset; opaque src_user<>; charset
dst_charset; opaque dst_user<>`. The parser reads only two strings, so the
`src_charset` word is interpreted as the first string's length (e.g. 106 for
UTF-8) and the record overruns. Separately, `parse_string` does not round the
consumed length up to a 4-byte XDR boundary, so any field after a string whose
length is not a multiple of 4 (e.g. `direction` in `parse_extended_acl`) is
read from padding bytes.

### 1.5 sFlow v5 unknown-sample skip path over-reads — Confirmed

**Status: fixed 2026-09-04** (with regression tests in the parser's `tests` module).

`crates/rustflow_core/src/sflow_v5/parser.rs:98`

The `Sample::Unknown` branch calls `parse_sample_header`, which consumes
sequence number and source id (8–12 bytes) and returns `fail()` for any format
not in the `SampleFormat` enum, and then does `take(header.length)`. But
`length` already counts the bytes after the length word, so the skip overshoots
by 8–12 bytes and the next sample's format is read mid-record. Any
enterprise-specific sample format never reaches the skip and drops the
datagram outright.

**Fix:** for unknown formats read only `format` + `length` and `take(length)`.

### 1.6 IPFIX: zero-field template stalls `many0` and drops remaining sets — Confirmed

**Status: fixed 2026-09-04** (unit tests in the IPFIX parser's `tests` module; withdrawal pcap test in `tests/test_ipfix.py`).

`crates/rustflow_core/src/ipfix/parser.rs:96` (and the v9 sibling at
`netflow_v9/parser.rs:139`)

A template record with `field_count = 0` — which is how RFC 7011 §8.1 encodes a
template withdrawal — is stored as a real template. A later data set for that
ID makes `parse_record_from_fields` succeed without consuming input; nom 8's
`many0` turns that into `Err(Many0)`. The outer `many0` over sets treats the
error as end-of-input, so every following set in the packet (unrelated
templates and data included) is silently discarded. In NetFlow v9 the same
shape fails the whole packet because of `count`.

**Fix:** treat `field_count == 0` as a withdrawal (remove the template), and
guard record parsing so an empty field list does not enter `many0`.

### 1.7 IPFIX encoder cannot round-trip reduced-size fields — Confirmed

**Status: fixed 2026-09-04** (unit tests in the IPFIX parser's `tests` module; withdrawal pcap test in `tests/test_ipfix.py`).

`crates/rustflow_core/src/ipfix/encoder.rs:135` (and BasicList at `:172`)

The parser now decodes 3-byte integers into `Unsigned32`/`Signed32` and 5–7
byte integers into `Unsigned64`/`Signed64`, but `FieldValue::encode` writes each
variant at its native width (4 or 8 bytes) rather than `field.field_length`.
Re-encoding a parsed record (public `Encode` API, used by library callers)
produces a set whose data no longer lines up with the template the receiver
holds. Not reachable from `rustflow relay`, which forwards raw bytes.

**Fix:** have `DataRecord::encode` emit `field_length` bytes from
`to_be_bytes()` for fixed-length integer fields.

---

## 2. High: unbounded resource growth (DoS from untrusted UDP)

### 2.1 Per-source parsers and templates are never evicted; `cleanup()` is never called — Confirmed

`crates/rustflow/src/processor.rs:84`, `crates/rustflow_core/src/common/timeout_map.rs:45`

`v9_parsers` / `ipfix_parsers` are keyed by the UDP source address and never
removed; each new entry deep-clones the ~500-entry `IERegistry`.
`TimeoutHashMap::get` merely hides expired entries; the only thing that removes
them is `cleanup()`, which has no callers anywhere in the workspace (the only
reference is `SamplingRateCache::cleanup`, itself uncalled). Spoofed source
addresses or random `source_id` / `observation_domain_id` values grow memory
until OOM.

### 2.2 Relay `--preserve-source` opens one socket per exporter, never evicted — Confirmed

`crates/rustflow_relay/src/lib.rs:214`

Every distinct `(ip, port)` source gets a bound UDP socket (with a 4 MB
`SO_SNDBUF` request) plus four Prometheus label sets in a `HashMap` with no
eviction. Churning or spoofed source ports exhaust file descriptors, after
which `create_output` fails and every datagram from a new source is dropped.

### 2.3 Per-source-IP Prometheus labels grow without bound — Plausible

`crates/rustflow_collect/src/metrics.rs:228`

Every distinct source IP permanently creates several label sets plus a cache
entry, and `record_unknown_version` does so for any 2-byte datagram. A scan
from many spoofed addresses inflates `/metrics` to hundreds of MB.

### 2.4 Exporter flow cache has no size bound — Plausible

`crates/rustflow_export/src/flow/mod.rs:79`

Every new 5-tuple inserts an entry that lives until the inactive timeout. A
SYN flood with random ports on the captured interface accumulates millions of
entries before the first eviction pass.

---

## 3. High: silent data loss in the collector

### 3.1 pcap read loop ignores `SHUTDOWN`; second Ctrl-C skips finalization — Confirmed

`crates/rustflow_collect/src/lib.rs:147`

The pcap loops never poll the `SHUTDOWN` flag, so the first SIGINT does
nothing visible. The second one calls `process::exit(1)`, bypassing
`OutputWriter::finish` and the Parquet footer. Result: an unreadable
`.parquet` (or an unrenamed `.tmp` under `--interval`) with all buffered rows
lost.

### 3.2 Temp file renamed to final name even when Parquet finish failed — Confirmed

`crates/rustflow_collect/src/output.rs:274` and `:317`

`WriterKind::finish` swallows the `ParquetSink::finish` error and
`OutputWriter::finish` / `rotate_if_due` call `commit_file` unconditionally.
If the footer write fails (e.g. ENOSPC), the file is still renamed to its
glob-visible name and downstream tools cannot open it.

### 3.3 NDJSON / CSV / protobuf write errors discarded with `.ok()` — Confirmed

`crates/rustflow_collect/src/output.rs:219`–`239`, plus `WriterKind::flush`/`finish`

Every `write_all`, `write_record`, and `flush` on the text and protobuf sinks
discards its `io::Result`. `rustflow collect ... | head -1` keeps running at
full CPU forever after `head` exits (Rust ignores SIGPIPE); a full disk is
equally invisible and the process exits 0.

### 3.4 `flush_batch` drains builders before the write; failure loses the batch — Confirmed

`crates/rustflow_collect/src/parquet_sink.rs:138`

`builders.finish()` and `self.rows = 0` run before `ArrowWriter::write`. On a
write error up to 32 768 flows are gone, the sink keeps accepting rows, and
`finish()` later closes a well-formed file that silently lacks a row group.

### 3.5 Rotation only happens on the write path — Plausible

`crates/rustflow_collect/src/output.rs:295`

`rotate_if_due` is called only from writes, never from the background flusher.
When traffic stops, the last window's file stays open under its hidden `.tmp`
name, with rows still in memory, until the next flow arrives.

---

## 4. Medium: exporter / generator / capture

### 4.1 Options Data Records do not advance the IPFIX sequence number — Plausible

`crates/rustflow_export/src/exporter.rs:99`, `crates/rustflow_generate/src/lib.rs:371`

RFC 7011 §3.1: the sequence number counts all Data Records, including Options
Data Records; only Template records are exempt. Gap-checking collectors will
report a duplicate after every options export.

### 4.2 `send_flows` stops at the first send error and loses the remaining chunks — Plausible

`crates/rustflow_export/src/exporter.rs:154`

Flows were already removed from the cache, so a transient ENOBUFS drops every
later chunk and the sequence number is not advanced for them, hiding the loss.

### 4.3 packet_mmap frame returned to the kernel without a memory barrier — Plausible

`crates/rustflow_export/src/capture/mod.rs:267`

`tp_status` is written with a plain store and the shared header is accessed via
plain `&mut`. The packet_mmap docs require a full barrier before writing
`tp_status`; on weakly ordered CPUs the kernel can reuse the frame while the
packet bytes are still being read.

### 4.4 Generator target address uses `parse().unwrap()` — Plausible

**Status: fixed 2026-09-04** (`--host` is resolved with `ToSocketAddrs`; the socket binds to the target's address family).

`crates/rustflow_generate/src/lib.rs:313`

`--host collector.local` or `--host ::1` panics with `AddrParseError` (exit
101) instead of an argument error.

### 4.5 `--flows-per-packet` not validated against the datagram limit — Plausible

`crates/rustflow_generate/src/lib.rs:140`

Values above ~1393 (IPv4) / ~922 (IPv6) exceed 65 507 bytes and fail with
EMSGSIZE on the first data packet after templates were already sent; `-f 0`
sends empty data sets.

### 4.6 Relay trusts the requested socket buffer size — Plausible

`crates/rustflow_relay/src/lib.rs:350`

Linux silently clamps `SO_RCVBUF`/`SO_SNDBUF` to `net.core.rmem_max` /
`wmem_max`. The advertised 4 MB buffer is usually not in effect and kernel
receive-queue drops are not counted in any metric.

---

## 5. Medium: enrichment and readers

### 5.1 IPv4-mapped IPv6 addresses are never enriched — Plausible

`crates/rustflow_collect/src/enrich/engine.rs:250`

`::ffff:a.b.c.d` is looked up only in the IPv6 trie, which never holds IPv4
prefixes. Binding with `--host ::` makes every IPv4 exporter appear in mapped
form, so `sampler_address` enrichment silently yields nothing.

### 5.2 CSV prefixes with host bits become separate trie nodes — Plausible

`crates/rustflow_collect/src/enrich/engine.rs:163`

`10.0.0.1/8` and `10.0.0.2/8` are stored as two nodes with inconsistent
longest-prefix-match results and an inflated `loaded_rows` count. Normalize with
`IpNet::trunc()` on insert.

### 5.3 pcap per-packet error repeats forever through the `Iterator` — Plausible

`crates/rustflow/src/pcap_reader.rs:76`

`pcap-file` does not advance past a bad packet, so `read()` returns the same
`Err` on every call and `filter_map(Result::ok)` spins forever. `rustflow
collect` breaks on the first error, so only library users are affected.

### 5.4 `parse_udp_packet` ignores the pcap `datalink` — Plausible

`crates/rustflow_core/src/common/utils.rs:15`

Link layers are probed heuristically (Ethernet → SLL → skip 20 → raw IP).
DLT_NULL/loopback captures yield zero flows with no error, and DLT_RAW captures
can be mis-probed as SLL2. IP-fragmented export datagrams in a pcap are also
dropped because etherparse skips transport parsing on fragments.

### 5.5 `read()` returns `Ok(None)` for both timeout and "no flows in packet" — Plausible

`crates/rustflow/src/reader.rs:161`

The doc says `None` means timeout, but a template-only packet also yields
`None`, so a `while let Some(flow) = reader.read()?` loop exits on the first
template refresh.

### 5.6 Invalid UTF-8 in a string IE aborts the whole packet — Plausible

`crates/rustflow_core/src/common/parser.rs:57`

`string()` uses `map_opt` on `from_utf8`, so one Latin-1 byte in a vendor
string field fails every data set in the packet. Use `from_utf8_lossy` and trim
NUL padding.

---

## 6. IPFIX parser: efficiency, behaviour change, and cleanups

### 6.1 Registry lookup per field per record on the decode hot path — Confirmed

`crates/rustflow_core/src/ipfix/parser.rs:211`

`lookup_field_info` runs for every field of every record: a hash probe plus an
`Arc` clone per field, and a `String` + `Arc` allocation for every unregistered
(vendor) IE. The result depends only on the template. Resolve `(DataType,
Arc<str>)` once per template at install time and pass the resolved slice into
`parse_record_from_fields`. This is the dominant decode cost under musl per the
existing perf notes.

### 6.2 Scope field JSON keys and value types changed in raw output — Confirmed

`crates/rustflow_core/src/ipfix/parser.rs:211`

Scope fields now resolve through the registry, so raw NDJSON keys change from
numeric IE ids (`"302"`) to names (`"selectorId"`), and unregistered or
non-integer scope IEs change from integers to hex strings or addresses. This
is RFC-correct but an externally visible schema break; it deserves a changelog
entry, and callers using `IpfixParser::new(IERegistry::new(), …)` now get hex
strings for all scope values.

### 6.3 `scope_field_count` is never validated — Plausible

`crates/rustflow_core/src/ipfix/parser.rs:583`

RFC 7011 §3.4.2.1 says it MUST NOT be zero and must be ≤ `field_count`. The
parser stores and re-serializes whatever it receives.

### 6.4 `ipfix_extract_u32/u16/u8` silently truncate `Unsigned64` — Plausible

`crates/rustflow_core/src/common/common_flow.rs:677`

5–7 byte reduced-size fields now reach these helpers as `Unsigned64`, where
they used to be `OctetArray` (→ `None`). A value ≥ 2³² is now truncated to a
wrong number instead of being absent; the sampling-rate cache can be
overwritten with a truncated rate.

### 6.5 Cleanups (no functional impact)

- `parser.rs:95` — the two `parse_templated_records` branches are identical
  except for the `Record::Data` / `Record::OptionsData` wrapper; select the
  field slice and wrapper once, parse once.
- `parser.rs:99` — `records.into_iter().map(Record::Data).collect()`
  reallocates the Vec; have `many0` produce `Record` directly.
- `parser.rs:237` — the 3-byte and 5–7 byte arms could collapse into one
  `len @ (3 | 5..=7)` arm using `be_uint`/`be_int` (dropping the `be_u24` /
  `be_i24` imports), or at least be ordered 1, 2, 3, 4, 5..=7, 8.
- `parser.rs:211` — the `(DataType, Arc<str>)` type annotation is redundant.
- `parser.rs:272` — zero-length fixed fields yield `OctetArray([])` in IPFIX
  but `Null` in NetFlow v9; pick one rule and share it.
- `parser.rs:816` — `be_uint`/`be_int` belong in `common/parser.rs` next to
  `string()`/`vector()` so `netflow_v9::parse_field_value` (`:458`) can gain
  the same reduced-size arms instead of falling to `OctetArray` (which makes
  byte/packet counts read as zero in `CommonFlow`).
- `parser.rs:830` — `be_int` has no guard on `length`; a `debug_assert!((1..=8).contains(&length))` documents the contract.
- `parser.rs:855`–`875` — test helpers `message()`, `set()`, `field()`
  re-implement what `impl Encode for IpfixPacket / Set / FieldSpecifier`
  already provides; build the test packets with the encoder so the two
  layouts cannot drift.
- `parser.rs:181` — the "Unknown template" warning is keyed on
  `records.is_empty()`; a padding-only set for a known template warns
  spuriously. Check template presence instead.

---

## 7. Conventions

No `CLAUDE.md` or `.claude/rules` exist. `cargo fmt --check`, nightly `fmt`
with the unstable options in `rustfmt.toml`, and `cargo clippy --all-targets
-D warnings` all pass on `rustflow_core`.

---

## Suggested order of work

1. ~~NetFlow v9 `count` semantics (1.1)~~ — done.
2. ~~sFlow counter record, extended_gateway, extended_user, unknown-sample skip (1.2–1.5)~~ — done.
3. ~~Zero-field template handling / withdrawals (1.6) and encoder width (1.7)~~ — done.
4. Eviction for per-source parsers, templates, relay sockets, and metrics labels (2.x).
5. Collector error propagation and shutdown/finalize paths (3.x).
6. Per-template IE resolution in the IPFIX parser (6.1).
