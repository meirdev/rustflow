//! How fast captured IPFIX, NetFlow and sFlow datagrams parse, collect
//! into records, and come out as common flows:
//!
//! ```text
//! cargo run --release -p rustflow_core --example throughput -- capture.pcap [payload MB]
//! ```
//!
//! The capture's UDP payloads are read into memory first, up to the byte
//! budget (512 MB by default), so that only parsing and conversion are
//! timed. The capture is taken as NetFlow and IPFIX, or as sFlow with
//! `sflow` as a third argument. A first pass through the collector learns
//! the templates; the timed passes follow: one parsing alone, one
//! collecting, one collecting and making a common flow of every flow
//! record.

use std::collections::HashMap;
use std::fs::File;
use std::hint::black_box;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap_file::pcap::PcapReader;
use rustflow_core::convert::{Mapper, Received, Record};
use rustflow_core::dissect::udp_payload;
use rustflow_core::protocol::information_element::Registry;
use rustflow_core::protocol::{
    Family, ParseError, Protocol, ipfix, netflow_v5, netflow_v9, sflow_v5,
};
use rustflow_core::reader::Collector;

struct Datagram {
    exporter: SocketAddr,
    time: SystemTime,
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
    let family = match args.next().as_deref() {
        Some("sflow") => Family::Sflow,
        _ => Family::Netflow,
    };
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

    let mut collector = Collector::new(family, Registry::iana(), Duration::from_mins(10));
    let (warm_up, _) = collect(&datagrams, &mut collector);
    println!(
        "warm-up: {} records, {} datagrams failed to parse",
        warm_up.records, warm_up.errors
    );
    let mut parsers = HashMap::new();
    let (counts, elapsed) = parse(family, &datagrams, &mut parsers);
    report("parse", &counts, elapsed);
    let (counts, elapsed) = collect(&datagrams, &mut collector);
    report("parse + convert", &counts, elapsed);
    let (counts, elapsed) = flows(&datagrams, &mut collector);
    report("+ common flow", &counts, elapsed);
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
            time: Some(datagram.time),
        };
        records.clear();
        collector.collect(received, &datagram.payload, &mut records)?;
        Ok(records.len())
    })
}

/// The whole way: parsed, converted, and every flow record made a
/// [`CommonFlow`]. Counts the flows.
fn flows(datagrams: &[Datagram], collector: &mut Collector) -> (Counts, Duration) {
    let mut records: Vec<Record> = Vec::new();
    let mut mapper = Mapper::default();
    timed(datagrams, |datagram| {
        let received = Received {
            exporter: datagram.exporter,
            time: Some(datagram.time),
        };
        records.clear();
        collector.collect(received, &datagram.payload, &mut records)?;
        let mut flows = 0;
        for record in records.iter().filter(|record| !record.is_options()) {
            black_box(mapper.flow(record));
            flows += 1;
        }
        Ok(flows)
    })
}

/// Parsing alone, with the templated parsers kept per exporter as the
/// collector keeps them.
fn parse(
    family: Family,
    datagrams: &[Datagram],
    parsers: &mut HashMap<SocketAddr, (netflow_v9::Parser, ipfix::Parser)>,
) -> (Counts, Duration) {
    timed(datagrams, |datagram| {
        let payload = &datagram.payload;
        let parsers = parsers.entry(datagram.exporter).or_default();
        Ok(match Protocol::of(family, payload)? {
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

/// The UDP payloads of a capture, up to `budget` bytes of them.
fn read_datagrams(path: &str, budget: u64) -> io::Result<Vec<Datagram>> {
    let mut pcap = PcapReader::new(File::open(path)?).map_err(io::Error::other)?;
    let link_type = pcap.header().datalink.into();
    let mut datagrams = Vec::new();
    let mut bytes = 0;
    while bytes < budget
        && let Some(packet) = pcap.next_packet()
    {
        let packet = packet.map_err(io::Error::other)?;
        if let Some((exporter, payload)) = udp_payload(link_type, &packet.data) {
            bytes += payload.len() as u64;
            datagrams.push(Datagram {
                exporter,
                time: UNIX_EPOCH + packet.timestamp,
                payload: payload.to_vec(),
            });
        }
    }
    Ok(datagrams)
}
