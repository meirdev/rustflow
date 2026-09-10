use rustflow_enrich::{Row, Schema};

fn sample() -> Row {
    Schema::new(["a", "b", "c"]).row([Some("1".to_owned()), None, Some("3".to_owned())])
}

#[test]
fn get_distinguishes_missing_columns_from_empty_cells() {
    let row = sample();
    assert_eq!(row.get("a"), Some("1"));
    assert_eq!(row.get("b"), None);
    assert_eq!(row.get("c"), Some("3"));
    assert_eq!(row.get("missing"), None);
    assert_eq!(row.values()[2].as_deref(), Some("3"));
}

#[test]
fn iter_and_debug_skip_empty_cells() {
    let row = sample();
    assert_eq!(row.iter().collect::<Vec<_>>(), [("a", "1"), ("c", "3")]);
    assert_eq!(format!("{row:?}"), r#"{"a": "1", "c": "3"}"#);
}

#[test]
#[should_panic(expected = "row has 1 values for 2 columns")]
fn row_length_must_match_schema() {
    Schema::new(["a", "b"]).row([None]);
}

#[test]
fn rows_share_one_schema() {
    let schema = Schema::new(["a"]);
    let first = schema.row([Some("x".to_owned())]);
    let second = schema.row([Some("y".to_owned())]);
    assert_eq!(schema.columns(), ["a"]);
    assert_ne!(first, second);
    assert_eq!(first, first.clone());
}
