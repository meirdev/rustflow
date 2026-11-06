//! The UDP payloads of the repository's pcap fixtures, for tests.

use std::fs::File;
use std::path::Path;

use pcap_file::pcap::PcapReader;

use crate::dissect::udp_payload;

/// Every UDP payload of `tests/fixtures/pcap/{name}`.
pub(crate) fn udp_payloads(name: &str) -> Vec<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/pcap")
        .join(name);
    let file = File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut pcap = PcapReader::new(file).unwrap();
    let link_type = pcap.header().datalink.into();
    let mut payloads = Vec::new();
    while let Some(packet) = pcap.next_packet() {
        let packet = packet.unwrap();
        let (_, payload) = udp_payload(link_type, &packet.data).expect("a UDP datagram");
        payloads.push(payload.to_vec());
    }
    payloads
}
