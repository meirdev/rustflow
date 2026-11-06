use super::*;
use crate::bytes::Truncated;
use crate::protocol::ParseError;

const HEADER_SIZE: usize = 24;
const FLOW_RECORD_SIZE: usize = 48;

fn header_bytes(count: u16) -> Vec<u8> {
    [
        &VERSION.to_be_bytes()[..],
        &count.to_be_bytes(),
        &3_600_000u32.to_be_bytes(),
        &1_700_000_000u32.to_be_bytes(),
        &123u32.to_be_bytes(),
        &42u32.to_be_bytes(),
        &[1, 2],
        &(1u16 << 14 | 100).to_be_bytes(),
    ]
    .concat()
}

/// Padding bytes are set, to show they are skipped whatever they hold.
fn flow_record_bytes() -> Vec<u8> {
    [
        &[192, 0, 2, 1, 198, 51, 100, 1, 203, 0, 113, 1][..],
        &1u16.to_be_bytes(),
        &2u16.to_be_bytes(),
        &10u32.to_be_bytes(),
        &1500u32.to_be_bytes(),
        &3_540_000u32.to_be_bytes(),
        &3_599_000u32.to_be_bytes(),
        &1234u16.to_be_bytes(),
        &80u16.to_be_bytes(),
        &[0xee, 0x18, 6, 0x10],
        &64500u16.to_be_bytes(),
        &64501u16.to_be_bytes(),
        &[24, 16, 0xee, 0xee],
    ]
    .concat()
}

fn expected_header(count: u16) -> Header {
    Header {
        version: VERSION,
        count,
        sys_uptime: 3_600_000,
        unix_secs: 1_700_000_000,
        unix_nsecs: 123,
        flow_sequence: 42,
        engine_type: 1,
        engine_id: 2,
        sampling_interval: Sampling {
            mode: 1,
            interval: 100,
        },
    }
}

fn expected_flow_record() -> FlowRecord {
    FlowRecord {
        srcaddr: Ipv4Addr::new(192, 0, 2, 1),
        dstaddr: Ipv4Addr::new(198, 51, 100, 1),
        nexthop: Ipv4Addr::new(203, 0, 113, 1),
        input: 1,
        output: 2,
        d_pkts: 10,
        d_octets: 1500,
        first: 3_540_000,
        last: 3_599_000,
        srcport: 1234,
        dstport: 80,
        tcp_flags: 0x18,
        prot: 6,
        tos: 0x10,
        src_as: 64500,
        dst_as: 64501,
        src_mask: 24,
        dst_mask: 16,
    }
}

#[test]
fn wire_sizes_match_the_format() {
    assert_eq!(header_bytes(0).len(), HEADER_SIZE);
    assert_eq!(flow_record_bytes().len(), FLOW_RECORD_SIZE);
}

#[test]
fn parses_every_field() {
    let datagram = [header_bytes(2), flow_record_bytes(), flow_record_bytes()].concat();
    assert_eq!(
        parse(&datagram),
        Ok(Packet {
            header: expected_header(2),
            flow_records: vec![expected_flow_record(); 2],
        })
    );
}

#[test]
fn the_sampling_field_splits_into_mode_and_interval() {
    let sampling = |mode, interval| Sampling { mode, interval };
    assert_eq!(Sampling::from(0), sampling(0, 0));
    assert_eq!(Sampling::from(100), sampling(0, 100));
    assert_eq!(Sampling::from(1 << 14 | 0x3fff), sampling(1, 0x3fff));
    assert_eq!(Sampling::from(2 << 14 | 1), sampling(2, 1));
    assert_eq!(Sampling::from(3 << 14), sampling(3, 0));
    assert_eq!(Sampling::from(u16::MAX), sampling(3, 0x3fff));
}

#[test]
fn a_packet_may_carry_no_records() {
    let packet = parse(&header_bytes(0)).unwrap();
    assert!(packet.flow_records.is_empty());
}

#[test]
fn bytes_after_the_last_record_are_ignored() {
    let datagram = [header_bytes(1), flow_record_bytes(), vec![0xff; 5]].concat();
    assert_eq!(parse(&datagram).unwrap().flow_records.len(), 1);
}

#[test]
fn another_version_is_rejected() {
    let mut datagram = header_bytes(0);
    datagram[..2].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(parse(&datagram), Err(ParseError::Version(9)));
}

#[test]
fn fewer_records_than_the_count_is_truncated() {
    let datagram = [header_bytes(2), flow_record_bytes()].concat();
    assert!(matches!(parse(&datagram), Err(ParseError::Truncated(_))));
}

#[test]
fn a_short_header_is_truncated() {
    assert_eq!(
        parse(&header_bytes(0)[..HEADER_SIZE - 1]),
        Err(ParseError::Truncated(Truncated {
            requested: 2,
            available: 1
        }))
    );
}

/// What [`write`] makes of `flow_record_bytes`: padding as zeros.
fn written_flow_record_bytes() -> Vec<u8> {
    let mut bytes = flow_record_bytes();
    bytes[36] = 0;
    bytes[46..].fill(0);
    bytes
}

#[test]
fn writes_what_it_parses_with_zero_padding() {
    let datagram = [header_bytes(2), flow_record_bytes(), flow_record_bytes()].concat();
    let packet = parse(&datagram).unwrap();

    let mut written = Vec::new();
    write(&packet, &mut written).unwrap();

    assert_eq!(
        written,
        [
            header_bytes(2),
            written_flow_record_bytes(),
            written_flow_record_bytes()
        ]
        .concat()
    );
    assert_eq!(parse(&written), Ok(packet));
}

#[test]
fn the_count_written_is_the_number_of_flow_records() {
    let mut packet = parse(&[header_bytes(1), flow_record_bytes()].concat()).unwrap();
    packet.header.count = 99;
    let mut written = vec![0xab];
    write(&packet, &mut written).unwrap();
    assert_eq!(written[0], 0xab);
    assert_eq!(written[3..5], 1u16.to_be_bytes());
    assert_eq!(written.len(), 1 + HEADER_SIZE + FLOW_RECORD_SIZE);
}

#[test]
fn more_flow_records_than_a_count_holds_write_nothing() {
    let record = parse(&[header_bytes(1), flow_record_bytes()].concat())
        .unwrap()
        .flow_records
        .remove(0);
    let packet = Packet {
        header: expected_header(0),
        flow_records: vec![record; 65_536],
    };
    let mut written = Vec::new();
    assert_eq!(
        write(&packet, &mut written),
        Err(WriteError::TooLarge {
            field: "count",
            value: 65_536
        })
    );
    assert!(written.is_empty());
}

#[test]
fn sampling_fields_round_trip_and_reject_values_too_wide() {
    for field in [0, 100, (1 << 14) | 100, u16::MAX] {
        assert_eq!(u16::try_from(Sampling::from(field)), Ok(field));
    }
    let too_wide = |mode, interval| u16::try_from(Sampling { mode, interval });
    assert_eq!(
        too_wide(4, 0),
        Err(WriteError::TooLarge {
            field: "sampling mode",
            value: 4
        })
    );
    assert_eq!(
        too_wide(0, 0x4000),
        Err(WriteError::TooLarge {
            field: "sampling interval",
            value: 0x4000
        })
    );

    let mut packet = parse(&header_bytes(0)).unwrap();
    packet.header.sampling_interval.mode = 4;
    let mut written = Vec::new();
    assert!(write(&packet, &mut written).is_err());
    assert!(written.is_empty());
}

#[cfg(feature = "serde")]
#[test]
fn round_trips_through_serde() {
    let packet = parse(&[header_bytes(1), flow_record_bytes()].concat()).unwrap();
    let json = serde_json::to_value(&packet).unwrap();
    assert_eq!(
        json["sampling_interval"],
        serde_json::json!({ "mode": 1, "interval": 100 })
    );
    assert_eq!(json["flow_records"][0]["srcaddr"], "192.0.2.1");
    assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
}
