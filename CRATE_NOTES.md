# Notes on the crates behind the sinks

Written 2026-09-11, after stepping the `rustflow_sink` encoders back from
hand-written protobuf, `itoa` integers, and a custom address formatter to the
plain public APIs of `prost`, `csv`, `serde_json`, `arrow`, and `parquet`.
The custom code was faster but not worth its size; this file records what
the profiling taught us about each crate, so the knowledge outlives the code.

Numbers are `cargo bench -p rustflow_sink` on an Apple M1, one thread,
varied flows, three enrichment fields, a byte-counting null writer.
"Custom" is the state before the step back, "plain" is what is checked in
now. Absolute numbers drift about 8 % between runs on this machine.

| encoder | custom ns/flow | plain ns/flow | plain flows/s | what the custom code did |
| --- | ---: | ---: | ---: | --- |
| ndjson | 821 | 816 | 1.2 M | nothing; `serde_json` both times |
| csv | 700 | 1262 | 0.8 M | `itoa` integers, stack-buffer addresses |
| protobuf | 246 | 740 | 1.35 M | encoded straight into a buffer with `prost::encoding` |
| parquet | 491 | 869 | 1.15 M | stack-buffer addresses into the text columns |

The collector's decode path is the actual bottleneck today (see
`SINK_DESIGN.md` §14 and the musl notes below), so every plain encoder is
still faster than the flows the ingest side can produce. Revisit only if a
profile of the whole binary on the release target shows the encoder thread
saturated.

## `core::fmt` (std)

**What we measured.** Formatting through `write!("{v}")` was the single
largest cost of the CSV and Parquet encoders: 44 % of CSV samples and 34 %
of Parquet. Two things drive it. Integers go `fmt::write` → `pad_integral`
for every one of ~30 numeric columns. IPv6 addresses format each segment
with `LowerHex` through the generic machinery; `Ipv4Addr` has a fixed
15-byte buffer fast path, `Ipv6Addr` only a partial one that still formats
segments with `write!`. `macaddr`'s `Display` is six `{:02X}` calls.

**Upstream suggestion.** `Ipv6Addr`'s `Display` could write hex digits into
its stack buffer directly, the way `Ipv4Addr` writes decimal octets, and
skip `fmt::Arguments` per segment. That is a contained change in
`core::net::ip_addr`.

**Locally, without custom code.** `itoa` (and `ryu` for floats) is the
standard crate for this and is what `csv`'s own serde path uses internally.
One dependency, one call per integer. The address side has no equivalent
crate; if it matters again, formatting the address once per flow and
sharing the text between the CSV, Parquet, and JSON columns halves the cost
without any custom digit code.

## `macaddr`

**Display.** Six `{:02X}` calls per address. A 17-byte stack buffer with a
hex table would be about ten lines and byte-identical. Worth an upstream PR.

**serde.** The derived `Serialize` emits a byte sequence, so NDJSON writes
`src_mac` as `[0,17,34,51,68,85]` while CSV and Parquet write
`00:11:22:33:44:55` and `docs/output.md` says "string". `macaddr` could
branch on `is_human_readable()` like `IpAddr` does in serde itself. Until
then, a `#[serde(serialize_with)]` on the two MAC fields in `rustflow_core`
fixes the inconsistency on our side and is the right change regardless.

## `csv`

**What we measured.** `Writer::write_field` scans every field for
characters that need quoting and copies it twice, scratch buffer into the
writer's buffer and then out. Those two are 18 % and 18 % of the encoder.
Numbers and addresses can never need quoting, but the API has no way to say
so.

**Why `Writer::serialize` doesn't help.** Its serde path formats integers
with `itoa`, which is exactly what we want, but it cannot take `CommonFlow`:
the struct's `skip_serializing_if` attributes would drop absent optional
columns and misalign the row, and the MAC fields serialize as sequences,
which a flat record rejects. Both are serde-level facts, not `csv` bugs.

**Upstream suggestion.** A `write_field_unquoted` (or a per-field "known
safe" flag) that appends bytes without the quoting scan. The writer already
distinguishes the delimiter and terminator paths, so this is a small
addition, and it would let numeric columns skip the scan entirely.

## `serde_json`

**What we measured.** 38 % of the NDJSON encoder is `serialize_str`
escaping ~40 static keys and ~9 string values per line. 30 % is `memmove`
from about six tiny writes per field (quote, key, quote, colon, value,
comma) going through `BufWriter`. `#[serde(flatten)]` costs about 50 ns per
line because it forces map serialization without a known length.

**Locally, without custom code.** Serialize into a reusable `Vec<u8>` and
`write_all` it once, instead of handing `to_writer` a `BufWriter`. The
`Write` impl for `Vec<u8>` is a bounds check and a copy; `BufWriter::write`
is a method call with its own length check per fragment. The old
`output.rs` did this. Cheap to try, and it is the single change most likely
to move NDJSON.

**Upstream suggestion.** Keys from `serialize_field` are `&'static str`.
`serde_json` cannot cache "this key never needs escaping" across calls, but
its escape scan could take the no-escape fast path with a wider check
(`memchr`-style over the byte string) instead of the per-byte table lookup
it does today. That would help every struct-heavy workload, not only ours.

## `prost`

**What we measured.** With the derived message, 42 % of the encoder was
`malloc`/`free`: `flow_type` as a `String`, five IP and two MAC fields as
`Vec<u8>`, a `HashMap` plus a `String` per key and per value for the
enrichment map. About fifteen allocations per flow. A further 33 % was
building the message and `encoded_len`, which walks the message once for
the length prefix and once more per map entry. Under musl, whose allocator
is much slower than macOS's or glibc's, the allocation share grows (the
collector bench on the musl target measured malloc at around 3x the cost).

**Upstream suggestions.**

- Let `bytes` fields be fixed-size arrays (`[u8; 4]`, `[u8; 16]`) or a
  `Cow<[u8]>` in derived messages. Addresses are the common case of a
  fixed-length `bytes` field, and today they cost an allocation each.
- Cache the lengths of nested and map entries during
  `encode_length_delimited`, or provide an encode path that writes into a
  reserved prefix and back-patches the length, so a message is walked once.

**Locally, without custom code.** Two schema-level choices would have
removed most of the allocations without touching the encoder: addresses as
`fixed32`/`fixed64` pairs instead of `bytes`, and `flow_type` as an enum
instead of a string. Both are wire-format changes, so they are for the next
schema version, not this one. `#[prost(btree_map)]` makes map order
deterministic at no cost and is worth switching to for reproducible output.

### Other protobuf crates (researched 2026-09-11)

None of them can encode `CommonFlow` directly: every crate needs its own
message type, because none accepts `u8`, `u16`, `IpAddr`, or `MacAddr6`
as field types. The question is only which one builds that message with
the fewest allocations and the least code.

| crate | state | fields | maps | protoc | what it would change for us |
| --- | --- | --- | --- | --- | --- |
| `prost` 0.14 | active | owned (`String`, `Vec<u8>`) | `HashMap`/`BTreeMap` | no (derive) | current: ~15 allocations per flow |
| `quick-protobuf` 0.8.1 | no release since Nov 2022 | `Cow<str>`, `Cow<[u8]>` | `HashMap<Cow, Cow>` | no (`pb-rs`) | borrowed addresses and strings: the map is the only allocation left |
| `femtopb` 0.9 | active, small user base, `no_std` | `&str`, `&[u8]`, `Option`, `Repeated` | **none** | no (derive) | zero allocations, but the map must be written as `Repeated<Entry{1,2}>`, which is wire-identical to `map<string,string>`; needs an `unknown_fields` slot per message |
| `micropb` 0.6 | active, embedded focus | narrowed ints (`u8`/`u16` via `int_size`), `ArrayVec`/`heapless` or `Vec` containers | configurable | yes (or a prebuilt descriptor set) | fixed-size address containers with no heap; enrichment values still need growable strings |
| `protobuf` 3.x (rust-protobuf) | active | owned, `Bytes` with a feature | `HashMap` | yes (vendored crate available) | nothing over `prost` |
| `protobuf` 4.x (Google, same crate name) | official, new | owned, arena-backed | yes | yes, plus a C kernel (upb) via FFI | a C dependency in the musl static build for no gain here |

The two that remove the allocations without a hand-written wire encoder
are `quick-protobuf` and `femtopb`. Both borrow: an address becomes a
`&[u8]` over a local `octets()` array and an enrichment value stays the
`&str` it already is. With allocations at 42 % of the current encoder, the
expected effect is roughly 740 → 350 ns/flow, the rest being prost-style
double length computation and varints. `quick-protobuf` is the simpler fit
(it has maps) but has had no release in almost four years; `femtopb` is
maintained but needs the map spelled as repeated entries and its buffer
sized by `encoded_len` before each encode.

Neither is worth switching to while the encoder thread is not the
bottleneck. If it becomes one, `femtopb` is the candidate: derive-based
like `prost`, no `protoc`, and the map-as-repeated-entries trick keeps the
wire format unchanged for every existing reader.

## `arrow` and `parquet`

**What worked with the public API alone.** Delta encoding and no dictionary
on the nine high-cardinality columns, statistics only on the timestamp
columns, 32 768-row batches: 729 → 511 ns/flow and 24 % smaller files,
all through `WriterProperties`. Keep those settings; they are in
`parquet.rs` with the reasoning.

**Where the time goes now.** Roughly 57 % inside the column writer,
dominated by dictionary interning of the text columns (`ahash` plus
`memcmp` per value) and RLE of the indices. The Arrow builders themselves
are under 5 %. `StringBuilder` implements `fmt::Write`, so a value can be
formatted straight into the column buffer with no intermediate string;
that is what the encoder does.

**What we measured and rejected.** Storing addresses as
`FixedSizeBinary(16)` removes both the formatting and the interning cost
(26 % faster) but changes what every reader sees; the file must keep
addresses as strings. Dictionary off everywhere is fast and triples the
file. Multi-threaded column encoding through the crate's per-column writer
API measured 1.7x at four threads and was removed because the collector
wants the improvement single-threaded. All of these are reachable through
the crate's own API if the decision ever changes.

**Upstream suggestion.** None that the crate doesn't already offer. The one
wish is a cheaper dictionary interner for short high-repetition strings,
but that is deep in the column writer and not something to ask for lightly.

## `maxminddb` (enrichment)

**What we measured.** A tree walk alone is about 70 ns for a random IPv4;
adding `decode_path::<serde_json::Value>` for one field brings it to about
260 ns, because every decoded value allocates through serde. The
enrichment table decodes on every lookup after we dropped the offset cache.

**Upstream suggestion.** The crate has an internal borrowing value type in
its decoder that isn't public. Exposing a `maxminddb::Value<'a>` that
borrows strings from the mapped file would let callers read a field
without going through serde or allocating, which is what a per-flow lookup
wants. `decode_path::<&str>` already exists for the case where the type is
known.

## `prometheus`

In maintenance mode (0.14.0, March 2025). `prometheus-client` is the
Prometheus organization's own crate, actively released, with typed label
structs instead of string slices. Nothing the collector needs is missing
from `prometheus`; if a switch happens it should convert every metric in
one change rather than run two libraries side by side.

## The decision, in one paragraph

Plain crates, plain code. The custom encoders proved the ceiling (protobuf
at 4 M flows/s, Parquet at 2 M), and the numbers are in `SINK_DESIGN.md`
§14 if that ceiling is ever needed. Until a whole-binary profile on the
release target shows the encoder thread as the limit, the encoders stay as
the crates' own APIs write them, and the wins listed above under "locally,
without custom code" are the first things to try.
