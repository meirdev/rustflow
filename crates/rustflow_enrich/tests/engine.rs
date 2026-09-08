use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};

use rustflow_enrich::*;

fn config(path: &Path, reload: ReloadPolicy) -> EnrichmentConfig {
    EnrichmentConfig::new(
        path.to_owned(),
        SourceFormat::Csv(CsvLookup::Exact {
            key_column: "number".into(),
            key_type: KeyType::Number,
        }),
        vec!["name".into()],
        reload,
    )
    .unwrap()
}
fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "Timed out waiting for reload");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn protocol_enrichment_and_transactional_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    fs::write(&path, "number,name\n6,tcp\n17,udp\n").unwrap();
    let enrichment = Enrichment::new(config(&path, ReloadPolicy::Never)).unwrap();
    assert_eq!(enrichment.lookup(Key::Number(17)).unwrap()["name"], "udp");
    assert!(enrichment.lookup(Key::Number(999)).is_none());
    assert_eq!(enrichment.stats().loaded_rows, 2);
    fs::write(&path, "number,name\n17,partial\ninvalid,bad\n").unwrap();
    let error = enrichment.reload().unwrap_err();
    assert!(
        matches!(&error, Error::Load { path: p, .. } if p == &path),
        "{error}"
    );
    assert!(error.to_string().contains("invalid"), "{error}");
    assert_eq!(enrichment.lookup(Key::Number(17)).unwrap()["name"], "udp");
    assert_eq!(enrichment.stats().reload_failures, 1);
    assert!(enrichment.stats().last_error.is_some());
    fs::write(&path, "number,name\n17,UDP\n").unwrap();
    assert_eq!(enrichment.reload().unwrap(), 1);
    assert_eq!(enrichment.lookup(Key::Number(17)).unwrap()["name"], "UDP");
    assert!(enrichment.stats().last_error.is_none());
    assert_eq!(enrichment.stats().successful_loads, 2);
}

#[test]
fn prefix_lookup_accepts_ip_keys_and_returns_source_columns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net.csv");
    fs::write(
        &path,
        "net,name\n10.0.0.0/8,broad\n10.1.0.0/16,specific\n2001:db8::/32,v6\n",
    )
    .unwrap();
    let arg = format!(
        "type=prefix_lookup,source={},prefix_column=net,columns=name|net",
        path.display()
    );
    let enrichment = Enrichment::new(parse_enrich_arg(&arg).unwrap()).unwrap();
    let snapshot = enrichment.snapshot();
    let src = snapshot
        .lookup(Key::Ip("10.1.2.3".parse().unwrap()))
        .unwrap();
    assert_eq!(src["name"], "specific");
    assert_eq!(src["net"], "10.1.0.0/16");
    assert_eq!(
        snapshot
            .lookup(Key::Ip("2001:db8::1".parse().unwrap()))
            .unwrap()["name"],
        "v6"
    );
    assert!(snapshot.lookup(Key::Number(17)).is_none());
}

#[test]
fn interval_reload_and_prompt_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    fs::write(&path, "number,name\n17,udp\n").unwrap();
    let enrichment = Enrichment::new(config(
        &path,
        ReloadPolicy::Interval(Duration::from_millis(30)),
    ))
    .unwrap();
    fs::write(&path, "number,name\n17,new\n").unwrap();
    wait_for(|| enrichment.lookup(Key::Number(17)).unwrap()["name"] == "new");
    drop(enrichment);
    let enrichment = Enrichment::new(config(
        &path,
        ReloadPolicy::Interval(Duration::from_secs(3600)),
    ))
    .unwrap();
    let start = Instant::now();
    drop(enrichment);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn watch_reload_handles_edits_atomic_replacement_failure_and_recreation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("protocols.csv");
    fs::write(&path, "number,name\n17,udp\n").unwrap();
    let enrichment = Enrichment::new(config(
        &path,
        ReloadPolicy::Watch {
            debounce: Duration::from_millis(30),
        },
    ))
    .unwrap();
    fs::write(&path, "number,name\n17,edited\n").unwrap();
    wait_for(|| enrichment.lookup(Key::Number(17)).unwrap()["name"] == "edited");
    let replacement = dir.path().join("replacement.csv");
    fs::write(&replacement, "number,name\n17,replaced\n").unwrap();
    fs::rename(&replacement, &path).unwrap();
    wait_for(|| enrichment.lookup(Key::Number(17)).unwrap()["name"] == "replaced");
    fs::write(&path, "broken\n").unwrap();
    wait_for(|| enrichment.stats().reload_failures > 0);
    assert_eq!(
        enrichment.lookup(Key::Number(17)).unwrap()["name"],
        "replaced"
    );
    let failures = enrichment.stats().reload_failures;
    fs::remove_file(&path).unwrap();
    wait_for(|| enrichment.stats().reload_failures > failures);
    fs::write(&path, "number,name\n17,recreated\n").unwrap();
    wait_for(|| enrichment.lookup(Key::Number(17)).unwrap()["name"] == "recreated");
    // After all source events settle, unrelated writes and reads must not reload.
    thread::sleep(Duration::from_millis(150));
    let loads = enrichment.stats().successful_loads;
    fs::write(dir.path().join("unrelated"), "noise").unwrap();
    fs::read_to_string(&path).unwrap();
    thread::sleep(Duration::from_millis(150));
    assert_eq!(enrichment.stats().successful_loads, loads);
    let start = Instant::now();
    drop(enrichment);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn concurrent_readers_use_one_snapshot_for_multiple_keys() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ports.csv");
    fs::write(&path, "number,name\n53,old\n443,old\n").unwrap();
    let enrichment = Enrichment::new(config(&path, ReloadPolicy::Never)).unwrap();
    let old = enrichment.snapshot();
    let barrier = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let enrichment = &enrichment;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..2000 {
                    let snapshot = enrichment.snapshot();
                    let src = snapshot.lookup(Key::Number(53)).unwrap();
                    let dst = snapshot.lookup(Key::Number(443)).unwrap();
                    assert_eq!(src["name"], dst["name"]);
                }
            });
        }
        barrier.wait();
        for version in 0..30 {
            fs::write(&path, format!("number,name\n53,{version}\n443,{version}\n")).unwrap();
            enrichment.reload().unwrap();
        }
    });
    assert_eq!(old.lookup(Key::Number(53)).unwrap()["name"], "old");
}
