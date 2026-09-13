//! Where files go and when they rotate.
mod common;

use std::path::{Path, PathBuf};

use common::{SAMPLE, sample_flow, stamp};
use rustflow_sink::sink::destination::partition_path;
use rustflow_sink::sink::{Destination, RotatingSink};
use rustflow_sink::*;

#[test]
fn partition_levels_add_directories_by_time() {
    let root = Path::new("/data");
    let at = stamp(SAMPLE);
    assert_eq!(
        partition_path(root, 0, "flows", "parquet", at),
        PathBuf::from("/data/flows-20240102T150700Z.parquet")
    );
    assert_eq!(
        partition_path(root, 1, "flows", "ndjson", at),
        PathBuf::from("/data/2024/01/02/flows-20240102T150700Z.ndjson")
    );
    assert_eq!(
        partition_path(root, 2, "flows", "csv", at),
        PathBuf::from("/data/2024/01/02/15/flows-20240102T150700Z.csv")
    );
    assert_eq!(
        partition_path(root, 3, "flows", "parquet", at),
        PathBuf::from("/data/2024/01/02/15/05/flows-20240102T150700Z.parquet")
    );
    // The top of the hour lands in the `00` bucket.
    assert_eq!(
        partition_path(root, 3, "flows", "parquet", stamp(SAMPLE - 420)),
        PathBuf::from("/data/2024/01/02/15/00/flows-20240102T150000Z.parquet")
    );
    assert_eq!(
        partition_path(Path::new("out"), 1, "edge01", "parquet", at),
        PathBuf::from("out/2024/01/02/edge01-20240102T150700Z.parquet")
    );
}

#[test]
fn partitioned_window_is_aligned_to_the_interval() {
    let root = std::env::temp_dir().join("rustflow_sink_destination_test");
    std::fs::remove_dir_all(&root).ok();
    let dest = Destination::Partitioned {
        root: root.clone(),
        level: 0,
        prefix: "flows".into(),
        interval_secs: 600,
    };

    // 15:07 falls in the 15:00 window, which ends at 15:10.
    let opened = dest.open_for(stamp(SAMPLE), "ndjson").unwrap();
    assert_eq!(opened.rotate_at, Some(SAMPLE - 420 + 600));
    let pending = opened.pending.unwrap();
    assert_eq!(
        pending.final_path(),
        root.join("flows-20240102T150000Z.ndjson")
    );
    assert!(root.join(".flows-20240102T150000Z.ndjson.tmp").exists());
    assert!(!pending.final_path().exists());

    drop(opened.writer);
    pending.commit().unwrap();
    assert!(root.join("flows-20240102T150000Z.ndjson").exists());
    assert!(!root.join(".flows-20240102T150000Z.ndjson.tmp").exists());

    std::fs::remove_dir_all(&root).ok();
}

fn files_under(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn rotation_closes_the_previous_window_and_renames_it() {
    let root = std::env::temp_dir().join("rustflow_sink_rotating_test");
    std::fs::remove_dir_all(&root).ok();
    let metrics = OutputMetrics::new();
    let dest = Destination::Partitioned {
        root: root.clone(),
        level: 0,
        prefix: "flows".into(),
        interval_secs: 600,
    };

    let mut sink: Box<dyn FlowSink> = Box::new(
        RotatingSink::<Ndjson>::open_at(dest, Vec::new(), metrics.clone(), stamp(SAMPLE)).unwrap(),
    );
    sink.write(&sample_flow(), &Enriched::new(0)).unwrap();

    assert!(!sink.rotate_if_due(stamp(SAMPLE + 60)).unwrap());
    assert_eq!(files_under(&root), [".flows-20240102T150000Z.ndjson.tmp"]);

    assert!(sink.rotate_if_due(stamp(SAMPLE + 600)).unwrap());
    assert_eq!(
        files_under(&root),
        [
            ".flows-20240102T151000Z.ndjson.tmp",
            "flows-20240102T150000Z.ndjson"
        ]
    );
    let first = std::fs::read_to_string(root.join("flows-20240102T150000Z.ndjson")).unwrap();
    assert_eq!(first.lines().count(), 1);

    sink.finish().unwrap();
    assert_eq!(
        files_under(&root),
        [
            "flows-20240102T150000Z.ndjson",
            "flows-20240102T151000Z.ndjson"
        ]
    );
    assert_eq!(metrics.files.get(), 2);
    assert!(metrics.bytes.get() > 0);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn single_file_never_rotates_and_flushes_on_demand() {
    let path = std::env::temp_dir().join("rustflow_sink_single_file_test.ndjson");
    let mut sink = RotatingSink::<Ndjson>::open_at(
        Destination::File(path.clone()),
        Vec::new(),
        OutputMetrics::new(),
        stamp(SAMPLE),
    )
    .unwrap();
    sink.write(&sample_flow(), &Enriched::new(0)).unwrap();
    assert!(!sink.rotate_if_due(stamp(SAMPLE + 86_400)).unwrap());

    sink.flush().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

    Box::new(sink).finish().unwrap();
    std::fs::remove_file(&path).ok();
}
