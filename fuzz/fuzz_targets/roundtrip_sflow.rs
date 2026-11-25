#![no_main]

use libfuzzer_sys::fuzz_target;
use rustflow_core::sflow_v5::{self, Packet};

fn encode(packet: &Packet) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    sflow_v5::encode_packet(&mut out, packet)
        .is_ok()
        .then_some(out)
}

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = sflow_v5::parse(data) else {
        return;
    };
    let Some(written) = encode(&packet) else {
        return;
    };
    let again = sflow_v5::parse(&written).expect("a written packet parses");
    // Compared as they print: a NaN is not equal to itself.
    assert_eq!(format!("{packet:?}"), format!("{again:?}"));
    assert_eq!(encode(&again).as_deref(), Some(written.as_slice()));
});
