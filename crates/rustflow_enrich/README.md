# rustflow_enrich

Standalone source lookup and reload library. It has no dependency on other RustFlow
crates and does not know about flows, field names, output mappings, or collector metrics.
The collector's existing enrichment implementation remains separate.

## Components

- `lookup`: key types and parsing, shared row schema, exact `HashMap` storage, and
  IPv4/IPv6 prefix tries.
- `formats`: CSV and MMDB readers emit `(key, row)` pairs through a callback.
- `config`: source, selected columns, index options, and reload policy.
- `loader`: picks the table for a configuration, parses keys, and builds it from one file.
- `reload`: never, interval, or file watching using `notify-debouncer-full`.
- `engine`: owns a source, replaces immutable tables, and exposes load statistics.

Field extraction and output mapping belong to the consuming application. For example,
a collector adapter would read `flow.proto`, supply its numeric value to this library,
and map the returned `name` column to an output field. No adapter is installed into the
collector by this crate.

Both `ExactTable` and `PrefixTable` implement the read-only `Lookup` trait and are
built through their own `insert` methods. `ExactTable` keeps one map keyed by `Key`,
so a lookup only matches rows of the same key type; lookups take a borrowed `Key<'_>`, so
text lookups do not allocate. The `loader` module picks the table
for the configured format, parses keys before insertion, and wraps any failure in
`Error::Load` with the source path. The engine then shares the finished table as an
`Arc<dyn Lookup>` in immutable snapshots.

## Example

Given `protocols.csv`:

```csv
number,name
6,tcp
17,udp
```

```rust,no_run
use rustflow_enrich::{Enrichment, Key, parse_enrich_arg};

let config = parse_enrich_arg(
    "type=exact,format=csv,source=protocols.csv,key_column=number,\
     key_type=number,columns=name,reload=watch",
)?;
let protocols = Enrichment::new(config)?;
let row = protocols.lookup(Key::Number(17)).unwrap();
assert_eq!(row["name"], "udp");
# Ok::<(), rustflow_enrich::Error>(())
```

`lookup()` returns an owned row. For borrowed results or multiple lookups against
one consistent table, hold a snapshot:

```rust,no_run
# use rustflow_enrich::{Enrichment, Key};
# fn example(protocols: &Enrichment) {
let snapshot = protocols.snapshot();
let tcp = snapshot.lookup(Key::Number(6));
let udp = snapshot.lookup(Key::Number(17));
// Both results come from the same load, even if a reload occurs in between.
# }
```

## Configuration

`EnrichmentConfig::new(source, format, columns, reload)` validates options before
returning a configuration. Its fields are private and exposed through read-only
accessors; the argument parser uses the same constructor. Relative source paths
are resolved at construction, but files are opened only during loading. Reloads
reuse the validated configuration and still validate the source data.

| Parameter | Meaning |
| --- | --- |
| `type` | `prefix_lookup` or `exact` |
| `format` | `csv` or `mmdb`; otherwise inferred from the extension, ignoring case |
| `source` | Source file path |
| `prefix_column` | Required only for CSV prefix lookup |
| `key_column` | Required only for CSV exact lookup |
| `key_type` | Required only for CSV exact lookup: `number`, `ip`, or `text` |
| `columns` | Required source columns or MMDB dotted paths, separated by `\|` |
| `reload` | `never` (default), a duration such as `30s`, or `watch` |

These are library configuration arguments, not the current collector CLI syntax.
The library does not parse `fields=proto@name:protocol_name`: resolving `proto` and
naming `protocol_name` are responsibilities of the caller.

`reload=watch` uses a 250ms debounce. Programmatic configuration can supply
`ReloadPolicy::Watch { debounce }`. Parsed intervals must be at least 1ms; values
constructed directly in code are not range-checked.
Parameter values cannot contain commas in this syntax; programmatic configuration can
represent paths containing commas. Duplicate parameters and duplicate columns are rejected.

Examples:

```text
type=prefix_lookup,source=networks.csv,prefix_column=net,columns=owner|net,reload=1m
type=exact,source=hosts.csv,key_column=address,key_type=ip,columns=name
type=exact,source=ports.csv,key_column=port,key_type=number,columns=service
type=exact,source=labels.csv,key_column=id,key_type=text,columns=label
type=prefix_lookup,source=country.mmdb,columns=country.iso_code,reload=watch
```

MMDB supports prefix lookup only. Exact numeric keys parse to `u64`, so `017` and `17`
identify the same key. Exact IP keys normalize equivalent address spellings. Text keys
preserve their identity after CSV whitespace trimming. A lookup with the wrong key type
returns no match. Prefix lookup accepts only IP keys.

## Loading and lifetime

CSV headers are trimmed and must be unique and nonempty. Required key and requested
columns must exist. Only the requested `columns` are stored, for both CSV and MMDB; the
key column is included only if it is also listed in `columns`. Rows share one `Schema`
and hold values positionally; `Row::get` returns `None` for an empty cell.
Invalid or empty keys and malformed records fail the entire load. This is stricter than
the existing collector, which skips some invalid prefix rows. A valid header-only CSV
publishes an empty table. Duplicate keys use the last row. Prefixes are normalized to
network boundaries.

MMDB dotted paths select nested map keys. Missing paths and empty strings are omitted;
other values become strings, with arrays and objects represented as JSON. Corrupt data
and invalid path traversal fail the load. MMDB array indexing is not exposed in the
argument syntax.

Reload builds a full new table before replacing the snapshot. Failed reloads retain the
previous table. Explicit and scheduled loads are serialized. Existing snapshot handles
remain valid after reload and keep their previous data. The caller owns the ordering and
combination of lookups across multiple sources.

Watching is registered before the initial load. The parent directory is watched so
atomic file replacements and delete/recreate updates are detected. Unrelated file events
and access events are ignored. Watch behavior depends on the platform's native filesystem
notifications; it does not follow changes to a symlink target in a different directory or
re-register a parent directory that is itself replaced.

Dropping the enrichment stops its watcher and wakes and joins its worker. Shutdown may
wait for an in-progress file load, but does not wait for the reload interval to expire.
Keep the `Enrichment` alive for as long as automatic reload is needed.

`Enrichment::stats()` exposes row count, successful loads, reload/watcher failures, the
last successful load time, and the latest error. A consuming application can export these
statistics through its own metrics registry.

## Validation

```bash
cargo test -p rustflow_enrich
cargo clippy -p rustflow_enrich --all-targets --no-deps -- -D warnings
```

Tests supply plain numeric, IP, and text keys. They include real filesystem watcher events
and a small synthetic MMDB generated locally; no database download or network access is
needed for tests.

Text keys use `Cow<str>`: insertion owns the stored text, while probes can borrow
with `Key::Text(text.into())`. `Key` is `Clone`, but no longer `Copy`. The exact
index uses `hashbrown` to support borrowed probes without allocating or tying
the returned row to the probe lifetime.
