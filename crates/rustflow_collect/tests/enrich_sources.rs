//! Every source kind against the `Source` trait: CSV exact, CSV prefix, MMDB.
use std::fs;
use std::path::{Path, PathBuf};

use rustflow_collect::enrich::*;

fn csv(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("source.csv");
    fs::write(&path, content).unwrap();
    path
}

fn exact(
    path: &Path,
    key_column: &str,
    key_type: KeyType,
    columns: &[&str],
) -> Result<Box<dyn Source>> {
    let schema = Schema::new(columns.iter().copied());
    source::csv::open(path, key_column, CsvLookup::Exact(key_type), &schema)
}

fn prefix(path: &Path, key_column: &str, columns: &[&str]) -> Result<Box<dyn Source>> {
    let schema = Schema::new(columns.iter().copied());
    source::csv::open(path, key_column, CsvLookup::Prefix, &schema)
}

fn mmdb(columns: &[&str]) -> MmdbSource {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.mmdb");
    MmdbSource::open(&path, &Schema::new(columns.iter().copied())).unwrap()
}

fn ip(addr: &str) -> Key<'static> {
    Key::Ip(addr.parse().unwrap())
}

/// The `column` value for `key`, or `None` when there is no row or no value.
fn value(source: &dyn Source, key: Key<'_>, column: &str) -> Option<String> {
    source
        .lookup(key)
        .and_then(|row| row.get(column).map(str::to_owned))
}

// ---------------------------------------------------------------------------
// CSV exact

#[test]
fn exact_keys_are_typed_and_duplicates_replace_previous_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv(dir.path(), "number,name\n017,old\n17,udp\n");
    let source = exact(&path, "number", KeyType::Number, &["name"]).unwrap();
    assert_eq!(source.len(), 1);
    assert_eq!(
        value(&*source, Key::Number(17), "name").as_deref(),
        Some("udp")
    );
    assert!(source.lookup(Key::Text("17".into())).is_none());
    assert!(source.lookup(Key::Number(6)).is_none());

    // An unparsable key fails the whole load.
    let path = csv(dir.path(), "number,name\n17,udp\nx,bad\n");
    assert!(exact(&path, "number", KeyType::Number, &["name"]).is_err());
}

#[test]
fn exact_ip_keys_normalize_spelling_and_do_not_match_subnets() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv(dir.path(), "address,name\n2001:0db8:0:0:0:0:0:1,host\n");
    let source = exact(&path, "address", KeyType::Ip, &["name"]).unwrap();
    assert_eq!(
        value(&*source, ip("2001:db8::1"), "name").as_deref(),
        Some("host")
    );
    assert!(source.lookup(ip("2001:db8::2")).is_none());

    let path = csv(dir.path(), "address,name\n2001:db8::/32,net\n");
    assert!(exact(&path, "address", KeyType::Ip, &["name"]).is_err());
}

#[test]
fn exact_text_keys_keep_their_spelling_and_accept_borrowed_probes() {
    use std::borrow::Cow;
    let dir = tempfile::tempdir().unwrap();
    let path = csv(dir.path(), "id,name\n017,text\n");
    let source = exact(&path, "id", KeyType::Text, &["name"]).unwrap();
    assert!(source.lookup(Key::Text("17".into())).is_none());
    let found = {
        let probe = String::from("017");
        source.lookup(Key::Text(Cow::Borrowed(&probe))).unwrap()
    };
    assert_eq!(found.get("name"), Some("text"));
}

// ---------------------------------------------------------------------------
// CSV prefix

#[test]
fn prefix_matches_longest_network_in_both_families() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv(
        dir.path(),
        "net,name\n0.0.0.0/0,default\n10.0.0.0/8,broad\n10.1.0.1/16,specific\n::/0,v6default\n2001:db8::/32,v6\n",
    );
    let source = prefix(&path, "net", &["name", "net"]).unwrap();
    assert_eq!(source.len(), 5);
    for (addr, expected) in [
        ("10.1.2.3", "specific"),
        ("10.2.1.1", "broad"),
        ("192.0.2.1", "default"),
        ("2001:db8::1", "v6"),
        ("::1", "v6default"),
    ] {
        assert_eq!(
            value(&*source, ip(addr), "name").as_deref(),
            Some(expected),
            "{addr}"
        );
    }
    // The key column is a regular column when requested, as written in the file.
    assert_eq!(
        value(&*source, ip("10.1.2.3"), "net").as_deref(),
        Some("10.1.0.1/16")
    );
    assert!(source.lookup(Key::Number(17)).is_none());

    // A bare address is not a prefix.
    let path = csv(dir.path(), "net,name\n10.0.0.1,bad\n");
    assert!(prefix(&path, "net", &["name"]).is_err());
}

// ---------------------------------------------------------------------------
// CSV reading

#[test]
fn csv_cells_are_trimmed_and_only_schema_columns_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv(
        dir.path(),
        "name, number ,empty\n\"UDP, transport\", 17 ,\n",
    );
    let source = exact(&path, "number", KeyType::Number, &["name", "empty"]).unwrap();
    let row = source.lookup(Key::Number(17)).unwrap();
    assert_eq!(row.get("name"), Some("UDP, transport"));
    assert_eq!(row.get("empty"), None);
    assert_eq!(row.get("number"), None);
    assert_eq!(row.values(), [Some("UDP, transport".to_owned()), None]);
    assert_eq!(row.iter().collect::<Vec<_>>(), [("name", "UDP, transport")]);
    assert_eq!(format!("{row:?}"), r#"{"name": "UDP, transport"}"#);

    assert!(exact(&path, "missing", KeyType::Number, &[]).is_err());
    assert!(exact(&path, "number", KeyType::Number, &["missing"]).is_err());
}

#[test]
fn csv_rejects_ambiguous_headers_and_malformed_records() {
    let dir = tempfile::tempdir().unwrap();
    for content in [
        "key,key\n1,2\n",
        "key, key \n1,2\n",
        "key,\n1,2\n",
        "key,name\n1\n",
        "key,name\n,x\n",
    ] {
        let path = csv(dir.path(), content);
        assert!(
            exact(&path, "key", KeyType::Text, &[]).is_err(),
            "{content:?}"
        );
    }
    // A header-only file is a valid, empty source.
    let path = csv(dir.path(), "key,name\n");
    let source = exact(&path, "key", KeyType::Text, &["name"]).unwrap();
    assert!(source.is_empty());
}

// ---------------------------------------------------------------------------
// MMDB (see fixtures/test.json for the records)

#[test]
fn mmdb_resolves_dotted_paths_and_renders_scalars_as_strings() {
    let source = mmdb(&[
        "country.iso_code",
        "country.names.en",
        "asn",
        "anycast",
        "empty",
        "tags",
        "missing.path",
    ]);
    let row = source.lookup(ip("1.2.3.4")).unwrap();
    assert_eq!(row.get("country.iso_code"), Some("AU"));
    assert_eq!(row.get("country.names.en"), Some("Australia"));
    assert_eq!(row.get("asn"), Some("13335"));
    assert_eq!(row.get("anycast"), Some("true"));
    assert_eq!(row.get("empty"), None);
    assert_eq!(row.get("tags"), None);
    assert_eq!(row.get("missing.path"), None);

    let row = source.lookup(ip("2001:db8::1")).unwrap();
    assert_eq!(row.get("country.iso_code"), Some("V6"));
    assert_eq!(row.get("tags"), Some(r#"["a","b"]"#));
    assert_eq!(row.get("asn"), None);
}

#[test]
fn mmdb_matches_longest_network_in_both_families() {
    let source = mmdb(&["country.iso_code"]);
    // Four records, but 10.1.0.0/16 splits 10.0.0.0/8 into eight tree networks.
    assert_eq!(source.len(), 11);
    for (addr, expected) in [
        ("10.1.2.3", Some("ZY")),
        ("10.2.0.1", Some("ZZ")),
        ("1.2.3.4", Some("AU")),
        ("2001:db8::1", Some("V6")),
        ("9.9.9.9", None),
        ("2001:db9::1", None),
    ] {
        assert_eq!(
            value(&source, ip(addr), "country.iso_code").as_deref(),
            expected,
            "{addr}"
        );
    }
    // A record without any requested column is not a match.
    let source = mmdb(&["asn"]);
    assert!(source.lookup(ip("10.2.0.1")).is_none());
    assert!(source.lookup(Key::Number(1)).is_none());
}

#[test]
fn mmdb_rejects_corrupt_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.mmdb");
    fs::write(&path, "not an mmdb").unwrap();
    assert!(MmdbSource::open(&path, &Schema::new(["x"])).is_err());
}
