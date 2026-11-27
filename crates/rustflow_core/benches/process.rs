//! Parsing datagrams and converting them to common flows, over the test
//! captures:
//!
//! ```sh
//! cargo bench -p rustflow_core --features pcap --bench process
//! ```

use std::hint::black_box;
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use jiff::Timestamp;
use rustflow_core::reader::{
    NetflowProcessor, PcapSource, Processor, Recv, SflowProcessor, Source,
};

struct Capture {
    datagrams: Vec<(IpAddr, Vec<u8>)>,
    received: Timestamp,
    now: Instant,
}

impl Capture {
    fn open(name: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pcap")
            .join(name);
        let mut source = PcapSource::open(path).expect("the capture opens");
        let mut datagrams = Vec::new();
        while let Recv::Datagram(datagram) = source.recv().expect("the capture reads") {
            datagrams.push((datagram.from.ip(), datagram.payload.to_vec()));
        }
        Self {
            datagrams,
            received: Timestamp::now(),
            now: Instant::now(),
        }
    }

    /// Reads every datagram, which leaves the processor knowing the
    /// capture's templates.
    fn process<P: Processor>(&self, processor: &mut P) -> usize {
        let mut flows = Vec::new();
        for (from, payload) in &self.datagrams {
            processor
                .process(*from, payload, self.received, self.now, &mut flows)
                .expect("the datagram parses");
        }
        flows.len()
    }
}

fn bench<P: Processor + Default>(criterion: &mut Criterion, name: &str, capture: &str) {
    let capture = Capture::open(capture);
    let mut processor = P::default();
    let flows = capture.process(&mut processor);

    let mut group = criterion.benchmark_group(name);
    group.throughput(Throughput::Elements(flows as u64));
    group.bench_function("parse", |bencher| {
        bencher.iter(|| {
            for (from, payload) in &capture.datagrams {
                black_box(processor.parse(*from, payload, capture.now)).expect("it parses");
            }
        });
    });
    group.bench_function("process", |bencher| {
        bencher.iter_batched_ref(
            || Vec::with_capacity(flows),
            |out| {
                for (from, payload) in &capture.datagrams {
                    processor
                        .process(*from, payload, capture.received, capture.now, out)
                        .expect("it parses");
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn benches(criterion: &mut Criterion) {
    bench::<NetflowProcessor>(criterion, "netflow_v5", "netflow_v5_sanity.pcap");
    bench::<NetflowProcessor>(criterion, "netflow_v9", "netflow_v9_sanity.pcap");
    bench::<NetflowProcessor>(criterion, "ipfix", "ipfix_sanity.pcap");
    bench::<SflowProcessor>(criterion, "sflow_v5", "sflow_v5_sanity.pcap");
}

criterion_group!(group, benches);
criterion_main!(group);
