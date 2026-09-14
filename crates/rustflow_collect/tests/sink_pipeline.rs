//! The encoder thread: draining, flushing on a deadline, and error reporting.
mod common;

use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::sample_flow;
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_sink::pipeline::{FlushTimer, SinkErrors};
use rustflow_sink::sink::{Destination, RotatingSink};
use rustflow_sink::*;

#[test]
fn encoder_loop_drains_every_chunk_then_finishes() {
    let path = std::env::temp_dir().join("rustflow_sink_pipeline_test.ndjson");
    let metrics = OutputMetrics::new();
    let sink: Box<dyn FlowSink> = Box::new(
        RotatingSink::<Ndjson>::open(
            Destination::File(path.clone()),
            vec!["src_asn".into()],
            metrics.clone(),
        )
        .unwrap(),
    );

    let (tx, rx) = mpsc::sync_channel(4);
    let producer = std::thread::spawn(move || {
        tx.send(vec![sample_flow(), sample_flow()]).unwrap();
        tx.send(vec![sample_flow()]).unwrap();
    });

    let enrich = |_: &CommonFlow, out: &mut Enriched| out.set(0, "13335");
    encoder_loop(rx, sink, 1, enrich, &metrics).unwrap();
    producer.join().unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 3);
    assert!(text.lines().all(|l| l.contains("\"src_asn\":\"13335\"")));
    assert_eq!(metrics.flows.get(), 3);

    std::fs::remove_file(&path).ok();
}

fn err() -> io::Result<()> {
    Err(io::Error::other("disk full"))
}

#[test]
fn a_not_due_rotation_does_not_clear_a_write_failure() {
    let metrics = OutputMetrics::new();
    let mut errors = SinkErrors::new(&metrics);

    errors.write(err());
    assert!(errors.write_failing());
    assert_eq!(metrics.write_errors.get(), 1);

    for _ in 0..100 {
        errors.rotate(Ok(false));
    }
    assert!(errors.write_failing());

    errors.write(err());
    assert_eq!(metrics.write_errors.get(), 2);
    assert_eq!(metrics.rotate_errors.get(), 0);

    errors.write(Ok(()));
    assert!(!errors.write_failing());
}

#[test]
fn rotation_failures_count_separately() {
    let metrics = OutputMetrics::new();
    let mut errors = SinkErrors::new(&metrics);
    errors.rotate(Err(io::Error::other("mkdir")));
    errors.rotate(Ok(true));
    assert_eq!(metrics.rotate_errors.get(), 1);
    assert_eq!(metrics.write_errors.get(), 0);
}

#[test]
fn a_steady_trickle_cannot_starve_the_flush_deadline() {
    let mut timer = FlushTimer::new(Duration::from_millis(40));
    let start = Instant::now();
    let mut fired = 0;
    while start.elapsed() < Duration::from_millis(250) {
        if timer.due() {
            fired += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!((4..=7).contains(&fired), "fired {fired} times");
}

#[test]
fn flush_timer_remaining_reaches_zero_and_fires_once() {
    let mut timer = FlushTimer::new(Duration::from_millis(20));
    assert!(timer.remaining() <= Duration::from_millis(20));
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(timer.remaining(), Duration::ZERO);
    assert!(timer.due());
    assert!(!timer.due());
}
