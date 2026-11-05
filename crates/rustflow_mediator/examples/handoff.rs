//! Measures the cost of handing chunks between component threads: two
//! collectors into one exporter, with processes between that allocate or
//! not, on the single-threaded pipeline and on the runner.
//!
//!     cargo run --release -p rustflow_mediator --example handoff

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{io, thread};

use rustflow_mediator::{Exporter, Item, Output, Pipeline, Process, Record, Runner, Schedule};
use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::value::Value;

const CHUNK: usize = 256;
const CHUNKS: usize = 8_000;
const RECORDS: usize = CHUNK * CHUNKS;

/// A NetFlow v5-sized record: the elements the converter gives one.
fn record(i: u32) -> Record {
    let elements: Arc<[ElementId]> = Arc::from([
        iana::SOURCE_IPV4_ADDRESS,
        iana::DESTINATION_IPV4_ADDRESS,
        iana::IP_NEXT_HOP_IPV4_ADDRESS,
        iana::INGRESS_INTERFACE,
        iana::EGRESS_INTERFACE,
        iana::PACKET_DELTA_COUNT,
        iana::OCTET_DELTA_COUNT,
        iana::FLOW_START_MILLISECONDS,
        iana::FLOW_END_MILLISECONDS,
        iana::SOURCE_TRANSPORT_PORT,
        iana::DESTINATION_TRANSPORT_PORT,
        iana::TCP_CONTROL_BITS,
        iana::PROTOCOL_IDENTIFIER,
        iana::IP_CLASS_OF_SERVICE,
        iana::BGP_SOURCE_AS_NUMBER,
        iana::BGP_DESTINATION_AS_NUMBER,
        iana::SOURCE_IPV4_PREFIX_LENGTH,
        iana::DESTINATION_IPV4_PREFIX_LENGTH,
        iana::ORIGINAL_EXPORTER_IPV4_ADDRESS,
        iana::COLLECTION_TIME_MILLISECONDS,
    ]);
    Record {
        protocol: rustflow_convert::Protocol::NetflowV5,
        sequence_number: i,
        scope: Vec::new(),
        elements,
        values: vec![
            Value::Ipv4Address([10, 0, 0, 1].into()),
            Value::Ipv4Address([10, 0, 0, 2].into()),
            Value::Ipv4Address([10, 0, 0, 3].into()),
            Value::Unsigned32(1),
            Value::Unsigned32(2),
            Value::Unsigned64(10),
            Value::Unsigned64(1000),
            Value::DateTimeMilliseconds(1_700_000_000_000),
            Value::DateTimeMilliseconds(1_700_000_001_000),
            Value::Unsigned16(443),
            Value::Unsigned16(51001),
            Value::Unsigned16(0x18),
            Value::Unsigned8(6),
            Value::Unsigned8(0),
            Value::Unsigned32(64496),
            Value::Unsigned32(64500),
            Value::Unsigned8(24),
            Value::Unsigned8(22),
            Value::Ipv4Address([192, 0, 2, 1].into()),
            Value::DateTimeMilliseconds(1_700_000_002_000),
        ],
    }
}

/// A correlation-like process: appends one element to every record,
/// which reallocates its element list and its values.
struct Tag;

impl Process for Tag {
    fn item(&mut self, item: Item, out: &mut Output) {
        match item {
            Item::Record(mut record) => {
                let mut elements = record.elements.to_vec();
                elements.push(iana::DOT1Q_VLAN_ID);
                record.elements = elements.into();
                record.values.push(Value::Unsigned16(7));
                out.record(record);
            }
            other => out.push(other),
        }
    }
}

/// A selection-like process: looks at every record, changes one value in
/// place, allocates nothing.
struct Touch;

impl Process for Touch {
    fn item(&mut self, item: Item, out: &mut Output) {
        match item {
            Item::Record(mut record) => {
                if let Some(Value::Unsigned64(octets)) = record.values.get_mut(6) {
                    *octets += 1;
                }
                out.record(record);
            }
            other => out.push(other),
        }
    }
}

/// Counts records and touches each one, as a serializer would.
struct Count(Arc<AtomicUsize>);

impl Exporter for Count {
    fn export(&mut self, items: &[Item]) -> io::Result<()> {
        let mut records = 0usize;
        for item in items {
            if let Item::Record(record) = item {
                std::hint::black_box(&record.values);
                records += 1;
            }
        }
        self.0.fetch_add(records, Ordering::Relaxed);
        Ok(())
    }
}

fn pipeline(processes: usize, allocating: bool, count: &Arc<AtomicUsize>) -> Pipeline {
    let mut builder = Pipeline::builder(["netflow", "sflow"]);
    let mut inputs = vec!["netflow".to_string(), "sflow".to_string()];
    for i in 0..processes {
        let name = format!("p{i}");
        let process: Box<dyn Process> = if allocating {
            Box::new(Tag)
        } else {
            Box::new(Touch)
        };
        builder = builder.process(&name, inputs.clone(), process);
        inputs = vec![name];
    }
    builder
        .exporter("files", inputs, Box::new(Count(Arc::clone(count))))
        .build()
        .unwrap()
}

fn chunks() -> Vec<Vec<Item>> {
    (0..CHUNKS)
        .map(|c| {
            (0..CHUNK)
                .map(|i| Item::Record(record((c * CHUNK + i) as u32)))
                .collect()
        })
        .collect()
}

fn single_thread(processes: usize, allocating: bool) -> Duration {
    let count = Arc::new(AtomicUsize::new(0));
    let mut pipeline = pipeline(processes, allocating, &count);
    let ids = [
        pipeline.source("netflow").unwrap(),
        pipeline.source("sflow").unwrap(),
    ];
    let chunks = chunks();
    let started = Instant::now();
    for (i, chunk) in chunks.into_iter().enumerate() {
        pipeline.push(ids[i % 2], chunk).unwrap();
    }
    pipeline.finish().unwrap();
    assert_eq!(count.load(Ordering::Relaxed), RECORDS);
    started.elapsed()
}

fn threaded(processes: usize, allocating: bool) -> Duration {
    let count = Arc::new(AtomicUsize::new(0));
    let pipeline = pipeline(processes, allocating, &count);
    let ids = [
        pipeline.source("netflow").unwrap(),
        pipeline.source("sflow").unwrap(),
    ];
    let mut runner = Runner::spawn(pipeline, Schedule::default(), |e| panic!("{e}")).unwrap();
    let mut streams = vec![Vec::new(), Vec::new()];
    for (i, chunk) in chunks().into_iter().enumerate() {
        streams[i % 2].push(chunk);
    }
    let started = Instant::now();
    let collectors: Vec<_> = ids
        .into_iter()
        .zip(streams)
        .map(|(id, chunks)| {
            let feed = runner.feed(id).unwrap();
            thread::spawn(move || {
                for chunk in chunks {
                    feed.push(chunk).unwrap();
                }
            })
        })
        .collect();
    for collector in collectors {
        collector.join().unwrap();
    }
    runner.finish().unwrap();
    assert_eq!(count.load(Ordering::Relaxed), RECORDS);
    started.elapsed()
}

fn main() {
    println!(
        "{RECORDS} records of 20 elements in chunks of {CHUNK}, two collectors into one exporter\n"
    );
    println!(
        "{:<14} {:>16} {:>16} {:>14} {:>16}",
        "processes", "single thread", "thread each", "per record", "per hand-off"
    );
    for (processes, allocating) in [(0, false), (1, false), (3, false), (1, true), (3, true)] {
        let single = single_thread(processes, allocating);
        let threads = threaded(processes, allocating);
        // Hand-offs: each chunk crosses one edge per component it reaches.
        let handoffs = CHUNKS * (processes + 1);
        let extra = threads.saturating_sub(single);
        let label = match (processes, allocating) {
            (0, _) => "none".to_string(),
            (n, false) => format!("{n} in place"),
            (n, true) => format!("{n} allocating"),
        };
        println!(
            "{:<14} {:>12.0} k/s {:>12.0} k/s {:>11} ns {:>13} ns",
            label,
            RECORDS as f64 / single.as_secs_f64() / 1e3,
            RECORDS as f64 / threads.as_secs_f64() / 1e3,
            threads.as_nanos() as usize / RECORDS,
            extra.as_nanos() as usize / handoffs,
        );
    }
}
