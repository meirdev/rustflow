use std::fs;
use std::path::{Path, PathBuf};

use rustflow_enrich::*;

fn schema(columns: &[&str]) -> Schema {
    Schema::new(columns.iter().copied())
}

fn csv_file(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("source.csv");
    fs::write(&path, content).unwrap();
    path
}

fn exact(key_column: &str, key_type: KeyType) -> CsvLookup {
    CsvLookup::Exact {
        key_column: key_column.into(),
        key_type,
    }
}

fn prefix(prefix_column: &str) -> CsvLookup {
    CsvLookup::Prefix {
        prefix_column: prefix_column.into(),
    }
}

#[test]
fn exact_keys_are_typed_and_duplicates_replace_previous_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv_file(dir.path(), "number,name\n017,old\n17,udp\n");
    let source =
        source::csv::open(&path, &exact("number", KeyType::Number), &schema(&["name"])).unwrap();
    assert_eq!(source.len(), 1);
    assert_eq!(
        source.lookup(Key::Number(17)).unwrap().get("name").unwrap(),
        "udp"
    );
    assert!(source.lookup(Key::Text("17".into())).is_none());
    assert!(source.lookup(Key::Number(6)).is_none());
    assert!(KeyType::Number.parse("-1").is_err());
    assert!(KeyType::Number.parse("18446744073709551616").is_err());

    // An unparsable key fails the whole load.
    let path = csv_file(dir.path(), "number,name\n17,udp\nx,bad\n");
    assert!(
        source::csv::open(&path, &exact("number", KeyType::Number), &schema(&["name"])).is_err()
    );
}

#[test]
fn exact_ip_keys_normalize_ipv6_and_do_not_match_subnets() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv_file(dir.path(), "address,name\n2001:0db8:0:0:0:0:0:1,host\n");
    let source =
        source::csv::open(&path, &exact("address", KeyType::Ip), &schema(&["name"])).unwrap();
    assert_eq!(
        source
            .lookup(Key::Ip("2001:db8::1".parse().unwrap()))
            .unwrap()
            .get("name")
            .unwrap(),
        "host"
    );
    assert!(
        source
            .lookup(Key::Ip("2001:db8::2".parse().unwrap()))
            .is_none()
    );
    assert!(KeyType::Ip.parse("2001:db8::/32").is_err());
}

#[test]
fn exact_text_preserves_text_identity_and_borrowed_probes_do_not_limit_row_lifetime() {
    use std::borrow::Cow;
    let dir = tempfile::tempdir().unwrap();
    let path = csv_file(dir.path(), "id,name\n017,text\n");
    let source = source::csv::open(&path, &exact("id", KeyType::Text), &schema(&["name"])).unwrap();
    assert!(source.lookup(Key::Text("17".into())).is_none());
    let found = {
        let probe = String::from("017");
        source.lookup(Key::Text(Cow::Borrowed(&probe))).unwrap()
    };
    assert_eq!(found.get("name").unwrap(), "text");
}

#[test]
fn key_type_parses_into_the_matching_key_variant() {
    assert_eq!(KeyType::Number.parse("17").unwrap(), Key::Number(17));
    assert_eq!(
        KeyType::Ip.parse("10.0.0.1").unwrap(),
        Key::Ip("10.0.0.1".parse().unwrap())
    );
    assert_eq!(KeyType::Text.parse("017").unwrap(), Key::Text("017".into()));
    assert!(KeyType::Number.parse("x").is_err());
    assert_eq!("number".parse::<KeyType>().unwrap(), KeyType::Number);
    assert!("bad".parse::<KeyType>().is_err());
}

#[test]
fn prefix_matches_longest_network_in_both_families() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv_file(
        dir.path(),
        "net,name\n0.0.0.0/0,default\n10.0.0.0/8,broad\n10.1.0.1/16,specific\n::/0,v6default\n2001:db8::/32,v6\n",
    );
    let source = source::csv::open(&path, &prefix("net"), &schema(&["name"])).unwrap();
    assert_eq!(source.len(), 5);
    for (ip, expected) in [
        ("10.1.2.3", "specific"),
        ("10.2.1.1", "broad"),
        ("192.0.2.1", "default"),
        ("2001:db8::1", "v6"),
        ("::1", "v6default"),
    ] {
        assert_eq!(
            source
                .lookup(Key::Ip(ip.parse().unwrap()))
                .unwrap()
                .get("name")
                .unwrap(),
            expected
        );
    }
    assert!(source.lookup(Key::Number(17)).is_none());

    // A bare address is not a prefix.
    let path = csv_file(dir.path(), "net,name\n10.0.0.1,bad\n");
    assert!(source::csv::open(&path, &prefix("net"), &schema(&["name"])).is_err());
}

#[test]
fn csv_cells_are_trimmed_and_only_schema_columns_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = csv_file(
        dir.path(),
        "name, number ,empty\n\"UDP, transport\", 17 ,\n",
    );
    let source =
        source::csv::open(&path, &exact("number", KeyType::Number), &schema(&["name"])).unwrap();
    let row = source.lookup(Key::Number(17)).unwrap();
    assert_eq!(row.get("name").unwrap(), "UDP, transport");
    assert!(row.get("empty").is_none());
    // The key column is not retained unless requested.
    assert!(row.get("number").is_none());
    assert_eq!(row.values(), [Some("UDP, transport".to_owned())]);

    assert!(source::csv::open(&path, &exact("missing", KeyType::Number), &schema(&[])).is_err());
    assert!(
        source::csv::open(
            &path,
            &exact("number", KeyType::Number),
            &schema(&["missing"])
        )
        .is_err()
    );
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
        let path = csv_file(dir.path(), content);
        assert!(
            source::csv::open(&path, &exact("key", KeyType::Text), &schema(&[])).is_err(),
            "{content}"
        );
    }
}

#[test]
fn parser_scopes_options_and_infers_formats_without_flow_fields() {
    let config = parse_enrich_arg(
        "type=exact,source=PROTO.CSV,key_column=number,key_type=number,columns=name,reload=watch",
    )
    .unwrap();
    assert_eq!(
        config.format(),
        &SourceFormat::Csv(CsvLookup::Exact {
            key_column: "number".into(),
            key_type: KeyType::Number,
        })
    );
    assert!(matches!(config.reload(), ReloadPolicy::Watch { .. }));
    for arg in [
        "type=prefix_lookup,source=x.CSV,prefix_column=net,columns=a|b,reload=1h",
        "type=exact,format=csv,source=no_extension,key_column=id,key_type=text,columns=name",
        "type=exact,source=x.csv,key_column=address,key_type=ip,columns=name",
        "type=prefix_lookup,source=x.MMDB,columns=country.iso_code",
    ] {
        assert!(parse_enrich_arg(arg).is_ok(), "{arg}");
    }
    // An explicit format wins over a mismatched extension.
    let config = parse_enrich_arg(
        "type=exact,format=csv,source=x.mmdb,key_column=id,key_type=text,columns=name",
    )
    .unwrap();
    assert!(matches!(config.format(), SourceFormat::Csv(_)));
    let config =
        parse_enrich_arg("type=prefix_lookup,format=mmdb,source=x.csv,columns=name").unwrap();
    assert_eq!(config.format(), &SourceFormat::Mmdb);
}

#[test]
fn invalid_combinations_are_rejected_before_loading() {
    for arg in [
        "type=exact,source=x.csv,key_column=key,columns=name",
        "type=exact,source=x.mmdb,key_type=number,columns=name",
        "type=exact,source=x.csv,prefix_column=key,key_type=number,columns=name",
        "type=prefix_lookup,source=x.csv,key_column=key,columns=name",
        "type=prefix_lookup,source=x.mmdb,prefix_column=key,columns=name",
        "type=prefix_lookup,source=x.mmdb,key_type=ip,columns=name",
        "type=exact,source=x.csv,key_column=key,key_type=number,columns=name,reload=0s",
        "type=exact,source=x.csv,key_column=key,key_type=number,columns=name,type=exact",
        "type=exact,source=x.csv,key_column=key,key_type=number,columns=name|name",
        "type=exact,source=x.csv,key_column=key,key_type=bad,columns=name",
        "type=exact,source=x.csv,key_column=key,key_type=number,columns=name|",
        "type=exact,source=x.csv,key_column=key,key_type=number,fields=proto@name:p",
    ] {
        assert!(parse_enrich_arg(arg).is_err(), "{arg}");
    }
    let config =
        parse_enrich_arg("type=exact,source=x.csv,key_column=key,key_type=number,columns=name")
            .unwrap();
    assert!(
        EnrichmentConfig::new(
            config.source().to_owned(),
            config.format().clone(),
            vec![],
            config.reload(),
        )
        .is_err()
    );
}

#[test]
fn constructor_rejects_invalid_options_without_opening_source() {
    use std::time::Duration;
    let path = PathBuf::from("not-required-to-exist.mmdb");
    let columns = vec!["country.iso_code".into()];
    assert!(
        EnrichmentConfig::new(
            PathBuf::new(),
            SourceFormat::Mmdb,
            columns.clone(),
            ReloadPolicy::Never
        )
        .is_err()
    );
    // Only parsed input is range-checked; direct construction is the caller's call.
    assert!("0s".parse::<ReloadPolicy>().is_err());
    assert!("9s".parse::<ReloadPolicy>().is_err());
    assert_eq!(
        "10s".parse::<ReloadPolicy>().unwrap(),
        ReloadPolicy::Interval(Duration::from_secs(10))
    );
    assert!(
        EnrichmentConfig::new(
            path.clone(),
            SourceFormat::Mmdb,
            columns.clone(),
            ReloadPolicy::Interval(Duration::ZERO)
        )
        .is_ok()
    );
    assert!(
        EnrichmentConfig::new(
            path.clone(),
            SourceFormat::Csv(CsvLookup::Prefix {
                prefix_column: " ".into()
            }),
            columns.clone(),
            ReloadPolicy::Never
        )
        .is_err()
    );
    assert!(
        EnrichmentConfig::new(
            path.clone(),
            SourceFormat::Mmdb,
            vec!["name".into(), "name".into()],
            ReloadPolicy::Never
        )
        .is_err()
    );
    let config = EnrichmentConfig::new(
        path,
        SourceFormat::Mmdb,
        columns.clone(),
        ReloadPolicy::Never,
    )
    .unwrap();
    assert!(config.source().is_absolute());
    assert_eq!(config.columns(), columns);
    assert_eq!(config.format(), &SourceFormat::Mmdb);
}
