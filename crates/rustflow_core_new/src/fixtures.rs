//! The UDP payloads of the repository's pcap fixtures, for tests.

use std::fs;
use std::path::Path;

/// Every UDP payload of `tests/fixtures/pcap/{name}`: a little-endian pcap
/// of Ethernet frames, without VLAN tags, carrying IPv4 or IPv6.
pub(crate) fn udp_payloads(name: &str) -> Vec<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/pcap")
        .join(name);
    let pcap = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(pcap[..4], [0xd4, 0xc3, 0xb2, 0xa1], "a little-endian pcap");

    let mut payloads = Vec::new();
    // Past the global header, each packet: a 16-byte record header whose
    // third field is the captured length, then the frame.
    let mut rest = &pcap[24..];
    while !rest.is_empty() {
        let captured = u32::from_le_bytes(rest[8..12].try_into().unwrap());
        let (frame, after) = rest[16..].split_at(usize::try_from(captured).unwrap());
        rest = after;

        let ip = &frame[14..];
        let udp = match ip[0] >> 4 {
            4 => &ip[usize::from(ip[0] & 0x0f) * 4..],
            6 => &ip[40..],
            version => panic!("IP version {version}"),
        };
        payloads.push(udp[8..].to_vec());
    }
    payloads
}
