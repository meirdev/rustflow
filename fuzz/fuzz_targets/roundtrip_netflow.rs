#![no_main]

use std::fmt::Debug;
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use rustflow_core::reader::{NetflowPacket, NetflowProcessor, Processor};
use rustflow_core::{ipfix, netflow_v5, netflow_v9};

fn encode(packet: &NetflowPacket) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let written = match packet {
        NetflowPacket::V5(packet) => netflow_v5::encode_packet(&mut out, packet).is_ok(),
        NetflowPacket::V9(packet) => netflow_v9::encode_packet(&mut out, packet).is_ok(),
        NetflowPacket::Ipfix(packet) => ipfix::encode_packet(&mut out, packet).is_ok(),
    };
    written.then_some(out)
}

/// Compared as they print: a NaN is not equal to itself.
fn assert_same(first: &impl Debug, second: &impl Debug) {
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
}

fuzz_target!(|data: &[u8]| {
    let mut original = NetflowProcessor::default();
    let mut rewritten = NetflowProcessor::default();
    let from = [192, 0, 2, 1].into();
    let now = Instant::now();

    let mut rest = data;
    while let [high, low, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (datagram, tail) = tail.split_at(length);
        rest = tail;

        let written = (original.parse(from, datagram, now).ok())
            .and_then(|packet| Some((encode(&packet)?, packet)));
        let Some((written, mut packet)) = written else {
            // The second processor still learns what this datagram taught.
            let _ = rewritten.parse(from, datagram, now);
            continue;
        };
        let again = rewritten
            .parse(from, &written, now)
            .expect("a written packet parses");
        // The encoder pads a set to four octets where the message as sent
        // may not have, so the length of the message can differ.
        if let (NetflowPacket::Ipfix(packet), NetflowPacket::Ipfix(again)) = (&mut packet, &again) {
            packet.header.length = again.header.length;
        }
        assert_same(&packet, &again);
        assert_eq!(encode(&again).as_deref(), Some(written.as_slice()));
    }
});
