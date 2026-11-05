//! How fast captured IPFIX, NetFlow and sFlow datagrams parse, and collect
//! into records:
//!
//! ```text
//! cargo run --release -p rustflow_reader --example throughput -- capture.pcap [payload MB]
//! ```
//!
//! The capture's UDP payloads are read into memory first, up to the byte
//! budget (512 MB by default), so that only parsing and conversion are
//! timed. A first pass through the collector learns the templates; the
//! timed passes follow: one parsing alone, one collecting.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustflow_protocol::{ParseError, Protocol, ipfix, netflow_v5, netflow_v9, sflow_v5};
use rustflow_reader::{Collector, Received, Record};

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

struct Datagram {
    exporter: SocketAddr,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Counts {
    packets: u64,
    bytes: u64,
    errors: u64,
    records: u64,
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("a pcap path");
    let budget: u64 = args.next().map_or(512, |mb| mb.parse().expect("MB"));
    let datagrams = read_datagrams(&path, budget << 20)?;
    let bytes: u64 = datagrams.iter().map(|d| d.payload.len() as u64).sum();
    let exporters = datagrams
        .iter()
        .map(|d| d.exporter)
        .collect::<std::collections::HashSet<_>>()
        .len();
    println!(
        "{} datagrams, {:.1} MB, {exporters} exporters",
        datagrams.len(),
        bytes as f64 / 1e6
    );

    let mut collector = Collector::default();
    let (warm_up, _) = collect(&datagrams, &mut collector);
    println!(
        "warm-up: {} records, {} datagrams failed to parse",
        warm_up.records, warm_up.errors
    );
    let mut parsers = HashMap::new();
    let (counts, elapsed) = parse(&datagrams, &mut parsers);
    report("parse", &counts, elapsed);
    let (counts, elapsed) = collect(&datagrams, &mut collector);
    report("parse + convert", &counts, elapsed);
    Ok(())
}

fn report(name: &str, counts: &Counts, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    println!(
        "{name:<16} {:>7.3} s  {:>8.0} datagrams/s  {:>10.0} records/s  {:>7.1} MB/s",
        secs,
        counts.packets as f64 / secs,
        counts.records as f64 / secs,
        counts.bytes as f64 / 1e6 / secs
    );
}

/// Runs `each` on every datagram, counting the records it says it found.
fn timed(
    datagrams: &[Datagram],
    mut each: impl FnMut(&Datagram) -> Result<usize, ParseError>,
) -> (Counts, Duration) {
    let mut counts = Counts::default();
    let start = Instant::now();
    for datagram in datagrams {
        counts.packets += 1;
        counts.bytes += datagram.payload.len() as u64;
        match each(datagram) {
            Ok(records) => counts.records += records as u64,
            Err(_) => counts.errors += 1,
        }
    }
    (counts, start.elapsed())
}

fn collect(datagrams: &[Datagram], collector: &mut Collector) -> (Counts, Duration) {
    let mut records: Vec<Record> = Vec::new();
    timed(datagrams, |datagram| {
        let received = Received {
            exporter: datagram.exporter,
            time: None,
        };
        records.clear();
        collector.collect(received, &datagram.payload, &mut records)?;
        Ok(records.len())
    })
}

/// Parsing alone, with the templated parsers kept per exporter as the
/// collector keeps them.
fn parse(
    datagrams: &[Datagram],
    parsers: &mut HashMap<SocketAddr, (netflow_v9::Parser, ipfix::Parser)>,
) -> (Counts, Duration) {
    timed(datagrams, |datagram| {
        let payload = &datagram.payload;
        let parsers = parsers.entry(datagram.exporter).or_default();
        Ok(match Protocol::of(payload)? {
            Protocol::NetflowV5 => netflow_v5::parse(payload)?.flow_records.len(),
            Protocol::NetflowV9 => parsers
                .0
                .parse(payload)?
                .flow_sets
                .iter()
                .map(|set| match set {
                    netflow_v9::FlowSet::Data(data) => data.records.len(),
                    _ => 0,
                })
                .sum(),
            Protocol::Ipfix => parsers
                .1
                .parse(payload)?
                .sets
                .iter()
                .map(|set| match set {
                    ipfix::Set::Data(data) => data.records.len(),
                    _ => 0,
                })
                .sum(),
            Protocol::SflowV5 => sflow_v5::parse(payload)?.samples.len(),
        })
    })
}

/// The UDP payloads of a little-endian pcap, up to `budget` bytes of them.
fn read_datagrams(path: &str, budget: u64) -> io::Result<Vec<Datagram>> {
    let mut file = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut global = [0; PCAP_GLOBAL_HEADER_LEN];
    file.read_exact(&mut global)?;
    assert_eq!(
        global[..4],
        [0xd4, 0xc3, 0xb2, 0xa1],
        "a little-endian pcap"
    );
    let link_type = u32::from_le_bytes(global[20..24].try_into().unwrap());

    let mut datagrams = Vec::new();
    let mut bytes = 0;
    let mut header = [0; PCAP_RECORD_HEADER_LEN];
    let mut frame = Vec::new();
    while bytes < budget && file.read_exact(&mut header).is_ok() {
        let captured = u32::from_le_bytes(header[8..12].try_into().unwrap());
        frame.resize(captured as usize, 0);
        file.read_exact(&mut frame)?;
        if let Some((exporter, payload)) = rustflow_dissect::udp_payload(link_type, &frame) {
            bytes += payload.len() as u64;
            datagrams.push(Datagram {
                exporter,
                payload: payload.to_vec(),
            });
        }
    }
    Ok(datagrams)
}
