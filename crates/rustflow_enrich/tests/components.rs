use std::fs;

use rustflow_enrich::lookup::{ExactTable, Lookup, PrefixTable, parse_prefix};
use rustflow_enrich::{formats, *};

fn schema(columns: &[&str]) -> Schema {
    Schema::new(columns.iter().copied())
}
fn row(value: &str) -> Row {
    schema(&["name"]).row([Some(value.to_owned())])
}

#[test]
fn exact_keys_are_typed_and_duplicates_replace_previous_rows() {
    let mut table = ExactTable::default();
    table.insert(KeyType::Number.parse("017").unwrap(), row("old"));
    table.insert(KeyType::Number.parse("17").unwrap(), row("udp"));
    assert_eq!(table.len(), 1);
    assert_eq!(table.lookup(Key::Number(17)).unwrap()["name"], "udp");
    assert!(table.lookup(Key::Text("17".into())).is_none());
    assert!(KeyType::Number.parse("-1").is_err());
    assert!(KeyType::Number.parse("18446744073709551616").is_err());
    assert!(table.lookup(Key::Number(6)).is_none());
}

#[test]
fn exact_ip_keys_normalize_ipv6_and_do_not_match_subnets() {
    let mut table = ExactTable::default();
    table.insert(
        KeyType::Ip.parse("2001:0db8:0:0:0:0:0:1").unwrap(),
        row("host"),
    );
    assert_eq!(
        table
            .lookup(Key::Ip("2001:db8::1".parse().unwrap()))
            .unwrap()["name"],
        "host"
    );
    assert!(
        table
            .lookup(Key::Ip("2001:db8::2".parse().unwrap()))
            .is_none()
    );
    assert!(KeyType::Ip.parse("2001:db8::/32").is_err());
}

#[test]
fn exact_text_preserves_text_identity_without_allocating_on_lookup() {
    let mut table = ExactTable::default();
    table.insert(Key::Text("017".into()), row("text"));
    let probe = String::from("017");
    assert!(table.lookup(Key::Text("17".into())).is_none());
    assert_eq!(
        table.lookup(Key::Text(probe.as_str().into())).unwrap()["name"],
        "text"
    );
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
    let mut table = PrefixTable::default();
    for (net, value) in [
        ("0.0.0.0/0", "default"),
        ("10.0.0.0/8", "broad"),
        ("10.1.0.1/16", "specific"),
        ("::/0", "v6default"),
        ("2001:db8::/32", "v6"),
    ] {
        table.insert(parse_prefix(net).unwrap(), row(value));
    }
    for (ip, expected) in [
        ("10.1.2.3", "specific"),
        ("10.2.1.1", "broad"),
        ("192.0.2.1", "default"),
        ("2001:db8::1", "v6"),
        ("::1", "v6default"),
    ] {
        assert_eq!(
            table.lookup(Key::Ip(ip.parse().unwrap())).unwrap()["name"],
            expected
        );
    }
    assert!(table.lookup(Key::Number(17)).is_none());
    assert!(parse_prefix("10.0.0.1").is_err());
}

#[test]
fn csv_reader_is_independent_of_lookup_strategy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source");
    fs::write(&path, "name, number ,empty\n\"UDP, transport\", 17 ,\n").unwrap();
    let mut records = Vec::new();
    formats::csv::read(&path, "number", &schema(&["name"]), |key, fields| {
        records.push((key.to_owned(), fields));
        Ok(())
    })
    .unwrap();
    assert_eq!(records[0].0, "17");
    assert_eq!(records[0].1["name"], "UDP, transport");
    assert!(records[0].1.get("empty").is_none());
    // Only schema columns are stored; the key column is not retained unless requested.
    assert!(records[0].1.get("number").is_none());
    assert_eq!(records[0].1.schema().columns(), ["name"]);
    assert_eq!(records[0].1.values(), [Some("UDP, transport".to_owned())]);
    assert!(formats::csv::read(&path, "missing", &schema(&[]), |_, _| Ok(())).is_err());
    assert!(formats::csv::read(&path, "number", &schema(&["missing"]), |_, _| Ok(())).is_err());
}

#[test]
fn csv_rejects_ambiguous_headers_and_malformed_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.csv");
    for content in [
        "key,key\n1,2\n",
        "key, key \n1,2\n",
        "key,\n1,2\n",
        "key,name\n1\n",
        "key,name\n,x\n",
    ] {
        fs::write(&path, content).unwrap();
        assert!(
            formats::csv::read(&path, "key", &schema(&[]), |_, _| Ok(())).is_err(),
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
    use std::path::PathBuf;
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
    assert!("500us".parse::<ReloadPolicy>().is_err());
    assert_eq!(
        "1ms".parse::<ReloadPolicy>().unwrap(),
        ReloadPolicy::Interval(Duration::from_millis(1))
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

#[test]
fn exact_table_owns_keys_and_borrowed_probes_do_not_limit_row_lifetime() {
    use std::borrow::Cow;
    let mut table = ExactTable::default();
    {
        let source = String::from("17");
        table.insert(Key::Text(Cow::Borrowed(&source)), row("text"));
    }
    table.insert(Key::Number(17), row("number"));
    table.insert(Key::Ip("0.0.0.17".parse().unwrap()), row("ip"));
    assert_eq!(table.len(), 3);
    table.insert(
        Key::Text(Cow::Owned(String::from("17"))),
        row("replacement"),
    );
    assert_eq!(table.len(), 3);
    let found = {
        let probe = String::from("17");
        table.lookup(Key::Text(Cow::Borrowed(&probe))).unwrap()
    };
    assert_eq!(found["name"], "replacement");
    assert_eq!(table.lookup(Key::Number(17)).unwrap()["name"], "number");
    assert_eq!(
        table.lookup(Key::Ip("0.0.0.17".parse().unwrap())).unwrap()["name"],
        "ip"
    );
}
