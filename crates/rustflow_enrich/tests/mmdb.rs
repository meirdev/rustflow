use std::fs;

use rustflow_enrich::*;

// A tiny original MMDB fixture: one IPv4 tree node, both /1 networks pointing
// to the same record. Encoding is limited to the types needed by these tests.
fn string(value: &str) -> Vec<u8> {
    assert!(value.len() < 29);
    let mut out = vec![0x40 | value.len() as u8];
    out.extend(value.as_bytes());
    out
}
fn number(kind: u8, value: u8) -> Vec<u8> {
    if kind < 8 {
        vec![(kind << 5) | 1, value]
    } else {
        vec![1, kind - 7, value]
    }
}
fn map(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut out = vec![0xe0 | entries.len() as u8];
    for (key, value) in entries {
        out.extend(string(key));
        out.extend(value);
    }
    out
}
fn fixture() -> Vec<u8> {
    let record = map(vec![
        ("country", map(vec![("iso_code", string("ZZ"))])),
        ("asn", number(6, 42)),
        ("enabled", vec![1, 7]), // extended type 14, boolean true
        ("empty", string("")),
    ]);
    let metadata = map(vec![
        ("binary_format_major_version", number(5, 2)),
        ("binary_format_minor_version", number(5, 0)),
        ("build_epoch", number(9, 1)),
        ("database_type", string("RustFlow-Test")),
        (
            "description",
            map(vec![("en", string("Synthetic test database"))]),
        ),
        ("ip_version", number(5, 4)),
        ("languages", vec![0, 4]), // extended type 11, empty array
        ("node_count", number(6, 1)),
        ("record_size", number(5, 24)),
    ]);
    let mut bytes = vec![0, 0, 17, 0, 0, 17];
    bytes.extend([0; 16]);
    bytes.extend(record);
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(metadata);
    bytes
}

#[test]
fn mmdb_networks_nested_fields_numbers_booleans_and_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.mmdb");
    fs::write(&path, fixture()).unwrap();
    let config = parse_enrich_arg(&format!(
        "type=prefix_lookup,source={},columns=country.iso_code|asn|enabled|missing.path|empty",
        path.display()
    ))
    .unwrap();
    let enrichment = Enrichment::new(config).unwrap();
    assert_eq!(enrichment.stats().loaded_rows, 2);
    for addr in ["1.2.3.4", "192.0.2.1"] {
        let out = enrichment.lookup(Key::Ip(addr.parse().unwrap())).unwrap();
        assert_eq!(out["country.iso_code"], "ZZ");
        assert_eq!(out["asn"], "42");
        assert_eq!(out["enabled"], "true");
        assert!(out.get("missing.path").is_none());
        assert!(out.get("empty").is_none());
    }
    fs::write(&path, "corrupt mmdb").unwrap();
    assert!(enrichment.reload().is_err());
    assert_eq!(enrichment.stats().loaded_rows, 2);
}

#[test]
fn mmdb_values_keep_structured_json() {
    use rustflow_enrich::formats::mmdb::value_to_string;
    assert_eq!(
        value_to_string(serde_json::json!([1, "two"])).as_deref(),
        Some("[1,\"two\"]")
    );
    assert_eq!(value_to_string(serde_json::Value::Null), None);
}
