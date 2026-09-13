//! Parsing of the `--enrich` syntax, reload policies, and typed keys.
//! Nothing here opens a file.
use std::path::PathBuf;
use std::time::Duration;

use rustflow_collect::enrich::config::{DEFAULT_DEBOUNCE, MIN_INTERVAL};
use rustflow_collect::enrich::*;

fn mapping(key: &str, source: &str, output: &str) -> FieldMapping {
    FieldMapping {
        key: key.parse().unwrap(),
        source_column: source.into(),
        output_field: output.into(),
    }
}

#[test]
fn fields_map_flow_keys_to_source_columns_and_output_names() {
    let config = parse_enrich_arg(
        "type=prefix_lookup,source=GeoLite2-City.mmdb,fields=src_addr@country.iso_code:src_country|city.names.en:src_city;dst_addr@country.iso_code:dst_country,reload=1h",
    )
    .unwrap();
    assert_eq!(
        config.mappings,
        [
            mapping("src_addr", "country.iso_code", "src_country"),
            mapping("src_addr", "city.names.en", "src_city"),
            mapping("dst_addr", "country.iso_code", "dst_country"),
        ]
    );
    // Source columns are the distinct mapped columns, in first-use order.
    assert_eq!(
        config.source.columns(),
        ["country.iso_code", "city.names.en"]
    );
    assert_eq!(config.source.format(), &SourceFormat::Mmdb);
    assert_eq!(
        config.source.reload(),
        ReloadPolicy::Interval(Duration::from_secs(3600))
    );
    assert!(config.source.source().is_absolute());
}

#[test]
fn parser_scopes_options_and_infers_formats() {
    let config = parse_enrich_arg(
        "type=exact,source=PROTOCOLS.CSV,key_column=number,fields=proto@name:proto_name,reload=watch",
    )
    .unwrap();
    // The key type follows the flow field: proto is a number.
    assert_eq!(
        config.source.format(),
        &SourceFormat::Csv {
            key_column: "number".into(),
            lookup: CsvLookup::Exact(KeyType::Number),
        }
    );
    assert!(matches!(config.source.reload(), ReloadPolicy::Watch { .. }));
    let config = parse_enrich_arg(
        "type=exact,source=hosts.csv,key_column=address,fields=src_addr@name:src_host",
    )
    .unwrap();
    assert!(matches!(
        config.source.format(),
        SourceFormat::Csv {
            lookup: CsvLookup::Exact(KeyType::Ip),
            ..
        }
    ));
    for arg in [
        "type=prefix_lookup,source=x.CSV,key_column=net,fields=dst_addr@a:b|c:d",
        "type=prefix_lookup,format=csv,source=no_extension,key_column=net,fields=next_hop@a:b",
        "type=prefix_lookup,source=x.MMDB,fields=sampler_address@country.iso_code:exporter_country",
        "type=exact,source=ports.csv,key_column=port,fields=src_port@service:src_service;dst_port@service:dst_service",
        "fields=src_addr@asn:src_asn,source=asn.csv,key_column=net,type=prefix_lookup",
        " type = prefix_lookup , source = x.csv , key_column = net , fields = src_addr@a:b ",
    ] {
        assert!(parse_enrich_arg(arg).is_ok(), "{arg}");
    }
    // An explicit format wins over a mismatched extension.
    let config =
        parse_enrich_arg("type=exact,format=csv,source=x.mmdb,key_column=id,fields=proto@name:p")
            .unwrap();
    assert!(matches!(config.source.format(), SourceFormat::Csv { .. }));
}

#[test]
fn invalid_combinations_are_rejected() {
    for arg in [
        // missing pieces
        "source=x.csv,key_column=net,fields=dst_addr@a:b",
        "type=prefix_lookup,key_column=net,fields=dst_addr@a:b",
        "type=prefix_lookup,source=x.csv,fields=dst_addr@a:b",
        "type=prefix_lookup,source=x.csv,key_column=net",
        "type=exact,source=x.csv,fields=proto@a:b",
        "type=prefix_lookup,source=no_extension,key_column=net,fields=dst_addr@a:b",
        // options that do not belong to the format
        "type=prefix_lookup,source=x.mmdb,key_column=net,fields=dst_addr@a:b",
        "type=exact,source=x.mmdb,key_column=k,fields=dst_addr@a:b",
        "type=exact,source=x.csv,key_column=k,key_type=number,fields=proto@a:b",
        "type=prefix_lookup,source=x.csv,prefix_column=net,fields=dst_addr@a:b",
        // keys
        "type=prefix_lookup,source=x.csv,key_column=net,fields=proto@a:b",
        "type=exact,source=x.csv,key_column=k,fields=proto@a:b;src_addr@c:d",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=nope@a:b",
        // field syntax
        "type=prefix_lookup,source=x.csv,key_column=net,fields=a:b",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@:b",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a:",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a:b,c:d",
        // parameters
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a:b,type=exact",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a:b,key=dst_addr",
        "type=prefix_lookup,source=x.csv,key_column=,fields=dst_addr@a:b",
        "type=prefix_lookup,source=x.csv,key_column=net,fields=dst_addr@a:b,reload=0s",
        "type=nope,source=x.csv,key_column=net,fields=dst_addr@a:b",
    ] {
        assert!(parse_enrich_arg(arg).is_err(), "{arg}");
    }
}

#[test]
fn lookup_keys_are_the_address_and_integer_flow_fields() {
    let names: Vec<_> = LookupKey::all().map(LookupKey::name).collect();
    assert!(names.contains(&"src_addr"));
    assert!(names.contains(&"proto"));
    assert!(names.contains(&"bytes"));
    assert!(!names.contains(&"src_mac"));
    assert!(!names.contains(&"time_received_ns"));
    assert!(!names.contains(&"flow_type"));
    assert_eq!(
        "src_addr".parse::<LookupKey>().unwrap().key_type(),
        KeyType::Ip
    );
    assert_eq!(
        "dst_port".parse::<LookupKey>().unwrap().key_type(),
        KeyType::Number
    );
    let error = "nope".parse::<LookupKey>().unwrap_err().to_string();
    assert!(
        error.contains("src_addr") && error.contains("template_id"),
        "{error}"
    );
}

#[test]
fn reload_policy_parses_and_range_checks_intervals() {
    assert_eq!(
        "never".parse::<ReloadPolicy>().unwrap(),
        ReloadPolicy::Never
    );
    assert_eq!(
        "watch".parse::<ReloadPolicy>().unwrap(),
        ReloadPolicy::Watch {
            debounce: DEFAULT_DEBOUNCE
        }
    );
    assert_eq!(
        "10s".parse::<ReloadPolicy>().unwrap(),
        ReloadPolicy::Interval(MIN_INTERVAL)
    );
    assert!("9s".parse::<ReloadPolicy>().is_err());
    assert!("0s".parse::<ReloadPolicy>().is_err());
    assert!("soon".parse::<ReloadPolicy>().is_err());
}

#[test]
fn source_config_validates_without_opening_the_source() {
    let path = PathBuf::from("not-required-to-exist.mmdb");
    let columns = vec!["country.iso_code".to_owned()];
    let new = |source: PathBuf, format, columns: Vec<String>| {
        SourceConfig::new(source, format, columns, ReloadPolicy::Never)
    };
    assert!(new(PathBuf::new(), SourceFormat::Mmdb, columns.clone()).is_err());
    assert!(new(path.clone(), SourceFormat::Mmdb, vec![]).is_err());
    assert!(
        new(
            path.clone(),
            SourceFormat::Mmdb,
            vec!["a".into(), "a".into()]
        )
        .is_err()
    );
    let blank_key = SourceFormat::Csv {
        key_column: " ".into(),
        lookup: CsvLookup::Prefix,
    };
    assert!(new(path.clone(), blank_key, columns.clone()).is_err());
    // Direct construction is not range-checked.
    assert!(
        SourceConfig::new(
            path.clone(),
            SourceFormat::Mmdb,
            columns.clone(),
            ReloadPolicy::Interval(Duration::ZERO)
        )
        .is_ok()
    );
}

#[test]
fn key_type_parses_into_the_matching_key_variant() {
    assert_eq!(KeyType::Number.parse("17").unwrap(), Key::Number(17));
    assert!(KeyType::Number.parse("-1").is_err());
    assert!(KeyType::Number.parse("18446744073709551616").is_err());
    assert_eq!(
        KeyType::Ip.parse("10.0.0.1").unwrap(),
        Key::Ip("10.0.0.1".parse().unwrap())
    );
    assert!(KeyType::Ip.parse("2001:db8::/32").is_err());
    assert_eq!(KeyType::Text.parse("017").unwrap(), Key::Text("017".into()));
    assert!(key::parse_prefix("10.0.0.1").is_err());
    assert!(key::parse_prefix("10.0.0.0/8").is_ok());
}
