#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use rustflow_core::reader::{Processor, SflowPacket, SflowProcessor};
use rustflow_core::sflow_v5;

fuzz_target!(|data: &[u8]| {
    let mut processor = SflowProcessor;
    let from = [192, 0, 2, 1].into();
    let now = Instant::now();

    let Ok(packet) = processor.parse(from, data, now) else {
        return;
    };
    let mut flows = Vec::new();
    processor.convert(from, &packet, 0, now, &mut flows);
    assert_eq!(flows.len(), SflowProcessor::summary(&packet).flows);

    serde_json::to_writer(std::io::sink(), &packet).expect("a packet serializes");
    // Not every packet that parses can be written again, but writing must
    // not panic.
    let SflowPacket::V5(packet) = &packet;
    let _ = sflow_v5::encode_packet(&mut Vec::new(), packet);
});
