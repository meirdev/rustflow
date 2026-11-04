//! How fast captured IPFIX, NetFlow and sFlow datagrams parse, and convert
//! to records:
//!
//! ```text
//! cargo run --release -p rustflow_convert --example throughput -- capture.pcap [payload MB]
//! ```
//!
//! The capture's UDP payloads are read into memory first, up to the byte
//! budget (512 MB by default), so that only parsing and conversion are
//! timed. One parser and converter serve each exporter address, as in a
//! collector. A first pass learns the templates; the timed passes follow.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustflow_convert::{Received, Record, ipfix, netflow_v5, netflow_v9, sflow_v5};
use rustflow_protocol::ParseError;

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

struct Datagram {
    exporter: IpAddr,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Exporter {
    netflow_v9: (rustflow_protocol::netflow_v9::Parser, netflow_v9::Converter),
    ipfix: (rustflow_protocol::ipfix::Parser, ipfix::Converter),
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

    let mut state = HashMap::new();
    let warm_up = run(&datagrams, &mut state, false);
    println!(
        "warm-up: {} records, {} datagrams failed to parse",
        warm_up.0.records, warm_up.0.errors
    );
    for (name, convert) in [("parse", false), ("parse + convert", true)] {
        let (counts, elapsed) = run(&datagrams, &mut state, convert);
        report(name, &counts, elapsed);
    }
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

fn run(
    datagrams: &[Datagram],
    state: &mut HashMap<IpAddr, Exporter>,
    convert: bool,
) -> (Counts, Duration) {
    let mut counts = Counts::default();
    let mut records: Vec<Record> = Vec::new();
    let start = Instant::now();
    for datagram in datagrams {
        let received = Received {
            exporter: datagram.exporter,
            time: None,
        };
        let exporter = state.entry(datagram.exporter).or_default();
        counts.packets += 1;
        counts.bytes += datagram.payload.len() as u64;
        let parsed: Result<usize, ParseError> = match version(&datagram.payload) {
            Some(5) => rustflow_protocol::netflow_v5::parse(&datagram.payload).map(|packet| {
                if convert {
                    netflow_v5::convert(packet, &received, &mut records);
                    records.len()
                } else {
                    packet.flow_records.len()
                }
            }),
            Some(9) => exporter
                .netflow_v9
                .0
                .parse(&datagram.payload)
                .map(|packet| {
                    if convert {
                        exporter
                            .netflow_v9
                            .1
                            .convert(packet, &received, &mut records);
                        records.len()
                    } else {
                        packet
                            .flow_sets
                            .iter()
                            .map(|set| match set {
                                rustflow_protocol::netflow_v9::FlowSet::Data(data) => {
                                    data.records.len()
                                }
                                _ => 0,
                            })
                            .sum()
                    }
                }),
            Some(10) => exporter.ipfix.0.parse(&datagram.payload).map(|packet| {
                if convert {
                    exporter.ipfix.1.convert(packet, &received, &mut records);
                    records.len()
                } else {
                    packet
                        .sets
                        .iter()
                        .map(|set| match set {
                            rustflow_protocol::ipfix::Set::Data(data) => data.records.len(),
                            _ => 0,
                        })
                        .sum()
                }
            }),
            _ => rustflow_protocol::sflow_v5::parse(&datagram.payload).map(|packet| {
                if convert {
                    sflow_v5::convert(packet, &received, &mut records);
                    records.len()
                } else {
                    packet.samples.len()
                }
            }),
        };
        match parsed {
            Ok(count) => counts.records += count as u64,
            Err(_) => counts.errors += 1,
        }
        records.clear();
    }
    (counts, start.elapsed())
}

/// NetFlow and IPFIX put their version in the first two bytes; sFlow's
/// first four bytes are its version, 5, so its first two are 0.
fn version(payload: &[u8]) -> Option<u16> {
    let version = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    (version != 0).then_some(version)
}

/// The UDP payloads of a little-endian pcap of Ethernet frames, up to
/// `budget` bytes of them.
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
