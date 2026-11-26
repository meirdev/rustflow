#![no_main]

use std::time::Instant;

use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
use rustflow_core::reader::{NetflowPacket, NetflowProcessor, Processor};
use rustflow_core::{ipfix, netflow_v5, netflow_v9};

fuzz_target!(|data: &[u8]| {
    let mut processor = NetflowProcessor::default();
    let from = [192, 0, 2, 1].into();
    let now = Instant::now();
    let mut flows = Vec::new();
    let mut encoded = Vec::new();

    let mut rest = data;
    while let [high, low, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (datagram, tail) = tail.split_at(length);
        rest = tail;

        let Ok(packet) = processor.parse(from, datagram, now) else {
            continue;
        };
        flows.clear();
        processor.convert(from, &packet, 0, now, &mut flows);
        assert_eq!(flows.len(), NetflowProcessor::summary(&packet).flows);

        serde_json::to_writer(std::io::sink(), &packet).expect("a packet serializes");
        // Not every packet that parses can be written again, but writing
        // must not panic.
        encoded.clear();
        let _ = match &packet {
            NetflowPacket::V5(packet) => netflow_v5::encode_packet(&mut encoded, packet).is_ok(),
            NetflowPacket::V9(packet) => netflow_v9::encode_packet(&mut encoded, packet).is_ok(),
            NetflowPacket::Ipfix(packet) => ipfix::encode_packet(&mut encoded, packet).is_ok(),
        };
    }
    let _ = processor.process(from, rest, Timestamp::UNIX_EPOCH, now, &mut flows);
});
