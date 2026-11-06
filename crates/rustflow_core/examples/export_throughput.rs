//! How fast records export as NetFlow v5, NetFlow v9, IPFIX and sFlow
//! datagrams:
//!
//! ```text
//! cargo run --release -p rustflow_core --example export_throughput -- [records] [per packet]
//! ```
//!
//! The records, a million by default, are made first: NetFlow v5-shaped
//! flows of eighteen elements, all of one shape, so that only exporting is
//! timed. Each protocol gets an untimed pass over them to warm up, then
//! two timed ones, in packets of thirty records by default: one making the
//! packets, one making and writing them as datagrams.

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rustflow_core::convert::{Elements, Protocol, Record};
use rustflow_core::export::{ipfix, netflow_v5, netflow_v9, sflow_v5};
use rustflow_core::protocol;
use rustflow_core::protocol::information_element::iana;
use rustflow_core::protocol::value::Value;

type Error = Box<dyn std::error::Error>;

/// What a pass does with each batch of records: makes a packet of it, and
/// writes the packet when given a buffer.
trait Exporting {
    fn export(
        &mut self,
        records: &[Record],
        now: SystemTime,
        buf: Option<&mut Vec<u8>>,
    ) -> Result<(), Error>;
}

macro_rules! exporting {
    ($exporter:ty, $write:path) => {
        impl Exporting for $exporter {
            fn export(
                &mut self,
                records: &[Record],
                now: SystemTime,
                buf: Option<&mut Vec<u8>>,
            ) -> Result<(), Error> {
                let packet = self.export(records, now)?;
                match buf {
                    Some(buf) => $write(&packet, buf)?,
                    None => {
                        black_box(&packet);
                    }
                }
                Ok(())
            }
        }
    };
}

exporting!(netflow_v5::Exporter, protocol::netflow_v5::write);
exporting!(netflow_v9::Exporter, protocol::netflow_v9::write);
exporting!(ipfix::Exporter, protocol::ipfix::write);
exporting!(sflow_v5::Agent, protocol::sflow_v5::write);

fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let count: usize = args
        .next()
        .map_or(1_000_000, |n| n.parse().expect("records"));
    let per_packet: usize = args
        .next()
        .map_or(30, |n| n.parse().expect("records per packet"));
    let records = records(count);
    println!(
        "{count} records of {} elements, {per_packet} per packet\n",
        records[0].elements.len()
    );

    let boot = SystemTime::now() - Duration::from_secs(3600);
    let agent = || sflow_v5::Agent::new(Ipv4Addr::new(192, 0, 2, 1).into(), 1, boot);
    let v9 = || netflow_v9::Exporter::new(1, boot);
    let v5 = || netflow_v5::Exporter::new(boot);
    let ipfix = || ipfix::Exporter::new(1);

    println!(
        "{:<26} {:>8} {:>14} {:>14} {:>10}",
        "", "time", "packets/s", "records/s", "MB/s"
    );
    run("NetFlow v5", &records, per_packet, v5)?;
    run("NetFlow v9", &records, per_packet, v9)?;
    run("IPFIX", &records, per_packet, ipfix)?;
    run("sFlow", &records, per_packet, agent)?;
    Ok(())
}

fn run<E: Exporting>(
    name: &str,
    records: &[Record],
    per_packet: usize,
    new: impl Fn() -> E,
) -> Result<(), Error> {
    let now = SystemTime::now();
    let mut exporter = new();
    let mut buf = Vec::new();
    for batch in records.chunks(per_packet) {
        buf.clear();
        exporter.export(batch, now, Some(&mut buf))?;
    }

    let mut exporter = new();
    let start = Instant::now();
    for batch in records.chunks(per_packet) {
        exporter.export(batch, now, None)?;
    }
    report(
        &format!("{name} export"),
        records,
        per_packet,
        0,
        start.elapsed(),
    );

    let mut exporter = new();
    let mut bytes = 0;
    let start = Instant::now();
    for batch in records.chunks(per_packet) {
        buf.clear();
        exporter.export(batch, now, Some(&mut buf))?;
        bytes += buf.len();
        black_box(&buf);
    }
    report(
        &format!("{name} export + write"),
        records,
        per_packet,
        bytes,
        start.elapsed(),
    );
    Ok(())
}

fn report(name: &str, records: &[Record], per_packet: usize, bytes: usize, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let packets = records.len().div_ceil(per_packet);
    println!(
        "{name:<26} {secs:>6.3} s {:>12.0}/s {:>12.0}/s {:>8.1} MB/s",
        packets as f64 / secs,
        records.len() as f64 / secs,
        bytes as f64 / 1e6 / secs
    );
}

/// Flows of one shape with varying addresses, ports and counters.
fn records(count: usize) -> Vec<Record> {
    let elements = Arc::new(Elements::from(vec![
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
    ]));
    let start_ms = 1_700_000_000_000;
    (0..count as u32)
        .map(|i| Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::clone(&elements),
            values: vec![
                Value::Ipv4Address(Ipv4Addr::from(0x0a00_0000 | (i & 0xff_ffff))),
                Value::Ipv4Address(Ipv4Addr::from(0xc0a8_0000 | (i & 0xffff))),
                Value::Ipv4Address(Ipv4Addr::new(10, 0, 0, 1)),
                Value::Unsigned32(1 + i % 4),
                Value::Unsigned32(5 + i % 4),
                Value::Unsigned64(u64::from(1 + i % 100)),
                Value::Unsigned64(u64::from(64 + i % 1400) * u64::from(1 + i % 100)),
                Value::DateTimeMilliseconds(start_ms + u64::from(i % 60_000)),
                Value::DateTimeMilliseconds(start_ms + 60_000 + u64::from(i % 1_000)),
                Value::Unsigned16(1024 + (i % 60_000) as u16),
                Value::Unsigned16(if i % 2 == 0 { 443 } else { 53 }),
                Value::Unsigned16(if i % 2 == 0 { 0x18 } else { 0 }),
                Value::Unsigned8(if i % 2 == 0 { 6 } else { 17 }),
                Value::Unsigned8(0),
                Value::Unsigned32(64496 + i % 16),
                Value::Unsigned32(64512 + i % 16),
                Value::Unsigned8(24),
                Value::Unsigned8(16),
            ],
        })
        .collect()
}
