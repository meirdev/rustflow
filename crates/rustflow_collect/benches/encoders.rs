//! Encoder throughput: one fully populated flow, encoded repeatedly into a
//! byte-counting null writer, so the numbers are the encoder's own cost
//! with no disk or kernel in the way.
//!
//! Run with `cargo bench -p rustflow_collect` (release profile).

use std::hint::black_box;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use macaddr::MacAddr6;
use rustflow_collect::enrich::Enriched;
use rustflow_collect::sink::{Csv, Discard, FlowEncoder, Ndjson, Parquet, Protobuf};
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

const ENRICHED_FIELDS: [&str; 3] = ["src_asn", "src_org", "dst_country"];
const ENRICHED_VALUES: [&str; 3] = ["13335", "Cloudflare, Inc.", "US"];

const WARMUP_FLOWS: usize = 100_000;
const BATCH: usize = 10_000;

/// `BENCH_SECS` overrides the measurement window; `BENCH_ENCODER=csv`
/// runs a single encoder (with enrichment), which is what a profiler wants.
fn measure_for() -> Duration {
    std::env::var("BENCH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_secs(2), Duration::from_secs)
}

/// A `Write` that only counts.
struct Counting(Arc<AtomicU64>);

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Every field set, so each encoder pays for every column.
fn full_flow() -> CommonFlow {
    let mut f = CommonFlow::new(FlowType::NetflowV9);
    f.time_received_ns = Some(1_704_207_600_123_456_789);
    f.sequence_num = 4_242_424;
    f.sampling_rate = Some(1000);
    f.sampler_address = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    f.time_flow_start_ns = Some(1_704_207_599_000_000_000);
    f.time_flow_end_ns = Some(1_704_207_600_000_000_000);
    f.bytes = 1_234_567;
    f.packets = 890;
    f.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
    f.dst_addr = Some(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)));
    f.src_mac = Some(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
    f.dst_mac = Some(MacAddr6::new(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb));
    f.etype = Some(0x0800);
    f.proto = Some(6);
    f.src_port = Some(51234);
    f.dst_port = Some(443);
    f.in_if = Some(12);
    f.out_if = Some(34);
    f.ip_tos = Some(0x10);
    f.ip_ttl = Some(63);
    f.tcp_flags = Some(0x18);
    f.icmp_type = Some(0);
    f.icmp_code = Some(0);
    f.ipv6_flow_label = Some(0xabcde);
    f.fragment_id = Some(7);
    f.fragment_offset = Some(0);
    f.src_as = Some(64512);
    f.dst_as = Some(13335);
    f.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)));
    f.src_net = Some(24);
    f.dst_net = Some(20);
    f.bgp_next_hop = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    f.src_vlan = Some(100);
    f.dst_vlan = Some(200);
    f.observation_domain_id = Some(1);
    f.template_id = Some(256);
    f
}

/// A pool of distinct flows with realistic spread: a few thousand sources
/// talking to many destinations, random ports and counters, timestamps
/// advancing about a microsecond per flow, one flow in ten over IPv6.
/// Cycled through during the measurement so no two consecutive rows are
/// equal; this is what makes Parquet's dictionary and compression pay
/// their real cost.
fn varied_flows(count: usize) -> Vec<CommonFlow> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..count)
        .map(|i| {
            let mut f = full_flow();
            let r = next();
            let src = (r & 0xfff) as u32; // 4096 sources
            let dst = ((r >> 12) & 0xffff) as u32; // 65536 destinations
            f.time_received_ns = f.time_received_ns.map(|t| t + i as i64 * 1_037);
            f.time_flow_start_ns = f.time_flow_start_ns.map(|t| t + i as i64 * 1_037);
            f.time_flow_end_ns = f.time_flow_end_ns.map(|t| t + i as i64 * 1_037 + 250_000);
            f.sequence_num = i as u32;
            f.bytes = 64 + (next() % 1_400_000);
            f.packets = 1 + f.bytes / 900;
            f.src_port = Some((32768 + (next() % 28_000)) as u16);
            f.dst_port = Some([443u16, 80, 53, 8443, 22][(next() % 5) as usize]);
            f.proto = Some(if next() % 10 < 8 { 6 } else { 17 });
            f.fragment_id = Some(next() as u32);
            f.ipv6_flow_label = Some((next() & 0xfffff) as u32);
            if next() % 10 == 0 {
                f.src_addr = Some(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 1, 0, 0, 0, 0, src as u16,
                )));
                f.dst_addr = Some(IpAddr::V6(Ipv6Addr::new(
                    0x2606,
                    0x4700,
                    0,
                    0,
                    0,
                    0,
                    (dst >> 16) as u16,
                    dst as u16,
                )));
            } else {
                f.src_addr = Some(IpAddr::V4(Ipv4Addr::from(0x0a10_0000 | src)));
                f.dst_addr = Some(IpAddr::V4(Ipv4Addr::from(0x6810_0000 | dst)));
            }
            f.sampler_address = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, (src % 8) as u8)));
            f.in_if = Some(src % 16);
            f.out_if = Some(dst % 16);
            f.src_as = Some(64512 + src % 200);
            f.dst_as = Some(13335 + dst % 5000);
            f
        })
        .collect()
}

struct Result {
    name: &'static str,
    data: &'static str,
    enriched: bool,
    flows: usize,
    elapsed: Duration,
    bytes: u64,
}

fn bench<E: FlowEncoder>(
    name: &'static str,
    data: &'static str,
    pool: &[CommonFlow],
    names: &[String],
    enriched: &Enriched,
) -> Result {
    let bytes = Arc::new(AtomicU64::new(0));
    let mut encoder = E::open(Box::new(Counting(Arc::clone(&bytes))), names).unwrap();
    let mut cycle = pool.iter().cycle();

    for _ in 0..WARMUP_FLOWS {
        encoder
            .encode(black_box(cycle.next().unwrap()), black_box(enriched))
            .unwrap();
    }
    let warmup_bytes = bytes.load(Ordering::Relaxed);

    let start = Instant::now();
    let mut flows = 0;
    let measure_for = measure_for();
    while start.elapsed() < measure_for {
        for _ in 0..BATCH {
            encoder
                .encode(black_box(cycle.next().unwrap()), black_box(enriched))
                .unwrap();
        }
        flows += BATCH;
    }
    // Parquet writes its last batch and footer here; part of the cost.
    encoder.finish().unwrap();
    let elapsed = start.elapsed();

    Result {
        name,
        data,
        enriched: !names.is_empty(),
        flows,
        elapsed,
        bytes: bytes.load(Ordering::Relaxed) - warmup_bytes,
    }
}

fn main() {
    let constant = vec![full_flow()];
    let varied = varied_flows(65_536);

    let names: Vec<String> = ENRICHED_FIELDS.iter().map(|s| s.to_string()).collect();
    let mut enriched = Enriched::new(names.len());
    for (i, value) in ENRICHED_VALUES.iter().enumerate() {
        enriched.set(i, *value);
    }
    let none = Enriched::new(0);

    let only = std::env::var("BENCH_ENCODER").ok();
    let mut results = Vec::new();
    for (data, pool) in [("constant", &constant), ("varied", &varied)] {
        for with_enrichment in [false, true] {
            if only.is_some() && (!with_enrichment || data == "constant") {
                continue;
            }
            let (names, enriched): (&[String], &Enriched) = if with_enrichment {
                (&names, &enriched)
            } else {
                (&[], &none)
            };
            let wanted = |name: &str| only.as_deref().is_none_or(|o| o == name);
            if wanted("discard") {
                results.push(bench::<Discard>("discard", data, pool, names, enriched));
            }
            if wanted("ndjson") {
                results.push(bench::<Ndjson>("ndjson", data, pool, names, enriched));
            }
            if wanted("csv") {
                results.push(bench::<Csv>("csv", data, pool, names, enriched));
            }
            if wanted("protobuf") {
                results.push(bench::<Protobuf>("protobuf", data, pool, names, enriched));
            }
            if wanted("parquet") {
                results.push(bench::<Parquet>("parquet", data, pool, names, enriched));
            }
        }
    }

    println!(
        "{:<12} {:<9} {:<11} {:>14} {:>10} {:>11}",
        "encoder", "data", "enrichment", "flows/s", "ns/flow", "bytes/flow"
    );
    for r in &results {
        let secs = r.elapsed.as_secs_f64();
        let per_sec = r.flows as f64 / secs;
        let ns = secs * 1e9 / r.flows as f64;
        let bytes = r.bytes as f64 / r.flows as f64;
        println!(
            "{:<12} {:<9} {:<11} {:>14.0} {:>10.1} {:>11.1}",
            r.name,
            r.data,
            if r.enriched { "3 fields" } else { "none" },
            per_sec,
            ns,
            bytes
        );
    }
}
