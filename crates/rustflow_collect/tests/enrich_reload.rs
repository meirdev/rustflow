//! The engine's reload behaviour: explicit, interval, and watch, plus what
//! readers see while a reload is in flight.
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};

use rustflow_collect::enrich::*;

fn open(path: &Path, reload: ReloadPolicy) -> Table {
    Table::new(config(path, reload), &TableMetrics::new()).unwrap()
}

fn config(path: &Path, reload: ReloadPolicy) -> SourceConfig {
    SourceConfig::new(
        path.to_owned(),
        SourceFormat::Csv {
            key_column: "number".into(),
            lookup: CsvLookup::Exact(KeyType::Number),
        },
        vec!["name".into()],
        reload,
    )
    .unwrap()
}

/// A protocols CSV with one row, `17,<name>`.
fn write(path: &Path, name: &str) {
    fs::write(path, format!("number,name\n17,{name}\n")).unwrap();
}

fn name(enrichment: &Table) -> Option<String> {
    enrichment
        .lookup(Key::Number(17))
        .and_then(|row| row.get("name").map(str::to_owned))
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "Timed out waiting for reload");
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_name(enrichment: &Table, expected: &str) {
    wait_for(|| name(enrichment).as_deref() == Some(expected));
}

#[test]
fn explicit_reload_is_transactional_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    write(&path, "udp");
    let enrichment = open(&path, ReloadPolicy::Never);
    assert_eq!(name(&enrichment).as_deref(), Some("udp"));
    assert!(enrichment.lookup(Key::Number(999)).is_none());
    assert_eq!(enrichment.len(), 1);
    assert_eq!(enrichment.metrics().loaded_rows.get(), 1);
    assert_eq!(enrichment.metrics().loads_total.get(), 1);

    // A failed reload names the source, keeps the old table, and is counted.
    fs::write(&path, "number,name\n17,partial\ninvalid,bad\n").unwrap();
    let error = enrichment.reload().unwrap_err();
    assert!(
        matches!(&error, Error::Load { path: p, .. } if p == &path),
        "{error}"
    );
    assert!(error.to_string().contains("invalid"), "{error}");
    assert_eq!(name(&enrichment).as_deref(), Some("udp"));
    assert_eq!(enrichment.metrics().reload_failures_total.get(), 1);
    assert_eq!(enrichment.metrics().loaded_rows.get(), 1);

    write(&path, "UDP");
    assert_eq!(enrichment.reload().unwrap(), 1);
    assert_eq!(name(&enrichment).as_deref(), Some("UDP"));
    assert_eq!(enrichment.metrics().loads_total.get(), 2);
}

#[test]
fn interval_reload_picks_up_changes_and_shuts_down_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    write(&path, "udp");
    let enrichment = open(&path, ReloadPolicy::Interval(Duration::from_millis(30)));
    write(&path, "new");
    wait_for_name(&enrichment, "new");
    drop(enrichment);

    // Dropping does not wait for the next tick.
    let enrichment = open(&path, ReloadPolicy::Interval(Duration::from_secs(3600)));
    let start = Instant::now();
    drop(enrichment);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn watch_reload_handles_edits_atomic_replacement_failure_and_recreation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    write(&path, "udp");
    let enrichment = open(
        &path,
        ReloadPolicy::Watch {
            debounce: Duration::from_millis(30),
        },
    );

    write(&path, "edited");
    wait_for_name(&enrichment, "edited");

    let replacement = dir.path().join("replacement.csv");
    write(&replacement, "replaced");
    fs::rename(&replacement, &path).unwrap();
    wait_for_name(&enrichment, "replaced");

    fs::write(&path, "broken\n").unwrap();
    wait_for(|| enrichment.metrics().reload_failures_total.get() > 0);
    assert_eq!(name(&enrichment).as_deref(), Some("replaced"));

    let failures = enrichment.metrics().reload_failures_total.get();
    fs::remove_file(&path).unwrap();
    wait_for(|| enrichment.metrics().reload_failures_total.get() > failures);
    write(&path, "recreated");
    wait_for_name(&enrichment, "recreated");

    // After all source events settle, unrelated writes and reads must not reload.
    thread::sleep(Duration::from_millis(150));
    let loads = enrichment.metrics().loads_total.get();
    fs::write(dir.path().join("unrelated"), "noise").unwrap();
    fs::read_to_string(&path).unwrap();
    thread::sleep(Duration::from_millis(150));
    assert_eq!(enrichment.metrics().loads_total.get(), loads);

    let start = Instant::now();
    drop(enrichment);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn snapshots_are_stable_while_reloads_run() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ports.csv");
    fs::write(&path, "number,name\n53,old\n443,old\n").unwrap();
    let enrichment = open(&path, ReloadPolicy::Never);
    let old = enrichment.snapshot();
    let barrier = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let enrichment = &enrichment;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..2000 {
                    // Both keys come from the same load.
                    let snapshot = enrichment.snapshot();
                    let src = snapshot.lookup(Key::Number(53)).unwrap();
                    let dst = snapshot.lookup(Key::Number(443)).unwrap();
                    assert_eq!(src.get("name"), dst.get("name"));
                }
            });
        }
        barrier.wait();
        for version in 0..30 {
            fs::write(&path, format!("number,name\n53,{version}\n443,{version}\n")).unwrap();
            enrichment.reload().unwrap();
        }
    });
    // A snapshot taken before the reloads still answers from its own load.
    assert_eq!(
        old.lookup(Key::Number(53)).unwrap().get("name"),
        Some("old")
    );
}
