//! End-to-end PSAMP (RFC 5476) test: report interpretations and a Packet
//! Report carrying a data link frame section, fed through the processor as
//! raw IPFIX messages.

use std::net::{IpAddr, Ipv4Addr};

use rustflow_lib::NetflowProcessor;

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const OBS_DOMAIN: u32 = 1;

fn message(sets: &[Vec<u8>]) -> Vec<u8> {
    let length = 16 + sets.iter().map(Vec::len).sum::<usize>();
    let mut buf = Vec::with_capacity(length);
    buf.extend_from_slice(&10u16.to_be_bytes()); // version
    buf.extend_from_slice(&(length as u16).to_be_bytes());
    buf.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // export_time
    buf.extend_from_slice(&0u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&OBS_DOMAIN.to_be_bytes());
    for set in sets {
        buf.extend_from_slice(set);
    }
    buf
}

fn set(set_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&set_id.to_be_bytes());
    buf.extend_from_slice(&((4 + payload.len()) as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn field(id: u16, length: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
    buf
}

fn options_template(template_id: u16, scope_count: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&template_id.to_be_bytes());
    buf.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    buf.extend_from_slice(&scope_count.to_be_bytes());
    for (id, length) in fields {
        buf.extend_from_slice(&field(*id, *length));
    }
    buf
}

fn template(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&template_id.to_be_bytes());
    buf.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (id, length) in fields {
        buf.extend_from_slice(&field(*id, *length));
    }
    buf
}

/// A 46-byte Ethernet + IPv4 + UDP frame (12345 -> 53, 4 payload bytes).
fn sample_frame() -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet II
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst mac
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src mac
    frame.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
    // IPv4, header length 20, total length 32, ttl 64, proto UDP
    frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]);
    frame.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]);
    frame.extend_from_slice(&[0x40, 0x11, 0x00, 0x00]);
    frame.extend_from_slice(&[192, 0, 2, 1]); // src addr
    frame.extend_from_slice(&[198, 51, 100, 2]); // dst addr
    // UDP: 12345 -> 53, length 12
    frame.extend_from_slice(&[0x30, 0x39, 0x00, 0x35]);
    frame.extend_from_slice(&[0x00, 0x0c, 0x00, 0x00]);
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    frame
}

#[test]
fn psamp_packet_report_end_to_end() {
    let mut processor = NetflowProcessor::new();

    // Templates: Selector Report (256), Selection Sequence Report (257),
    // Packet Report (258, with a variable-length dataLinkFrameSection).
    let templates = message(&[
        set(
            3,
            &[
                options_template(256, 1, &[(302, 8), (304, 2), (305, 4), (306, 4)]),
                options_template(257, 1, &[(301, 8), (302, 8)]),
            ]
            .concat(),
        ),
        set(2, &template(258, &[(301, 8), (323, 8), (315, 0xffff)])),
    ]);
    assert!(processor.process(EXPORTER, &templates, None).is_empty());

    // Report interpretations: selector 5 is 1-in-100 systematic count-based
    // sampling; selection sequence 9 applies selector 5.
    let mut selector_report = Vec::new();
    selector_report.extend_from_slice(&5u64.to_be_bytes()); // selectorId
    selector_report.extend_from_slice(&1u16.to_be_bytes()); // selectorAlgorithm
    selector_report.extend_from_slice(&1u32.to_be_bytes()); // samplingPacketInterval
    selector_report.extend_from_slice(&99u32.to_be_bytes()); // samplingPacketSpace

    let mut sequence_report = Vec::new();
    sequence_report.extend_from_slice(&9u64.to_be_bytes()); // selectionSequenceId
    sequence_report.extend_from_slice(&5u64.to_be_bytes()); // selectorId

    let reports = message(&[set(256, &selector_report), set(257, &sequence_report)]);
    assert!(processor.process(EXPORTER, &reports, None).is_empty());

    // Packet Report: selection sequence 9, observation time, sampled frame.
    let frame = sample_frame();
    let mut packet_report = Vec::new();
    packet_report.extend_from_slice(&9u64.to_be_bytes()); // selectionSequenceId
    packet_report.extend_from_slice(&1_700_000_000_123u64.to_be_bytes()); // observationTimeMilliseconds
    packet_report.push(frame.len() as u8); // variable-length encoding
    packet_report.extend_from_slice(&frame);

    let flows = processor.process(EXPORTER, &message(&[set(258, &packet_report)]), None);
    assert_eq!(flows.len(), 1);

    let flow = &flows[0];
    assert_eq!(flow.selection_sequence_id, Some(9));
    assert_eq!(flow.sampling_rate, Some(100));
    assert_eq!(flow.packets, 1);
    assert_eq!(flow.bytes, frame.len() as u64);
    assert_eq!(flow.time_flow_start_ns, Some(1_700_000_000_123_000_000));
    assert_eq!(flow.time_flow_end_ns, Some(1_700_000_000_123_000_000));
    assert_eq!(flow.etype, Some(0x0800));
    assert_eq!(flow.src_addr, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert_eq!(
        flow.dst_addr,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
    );
    assert_eq!(flow.proto, Some(17));
    assert_eq!(flow.src_port, Some(12345));
    assert_eq!(flow.dst_port, Some(53));
    assert_eq!(flow.ip_ttl, Some(64));
    assert_eq!(flow.observation_domain_id, Some(OBS_DOMAIN));
    assert_eq!(flow.template_id, Some(258));
}
