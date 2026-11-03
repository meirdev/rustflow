use std::net::Ipv4Addr;

use super::*;
use crate::fixtures::udp_payloads;
use crate::{ParseError, WriteError};

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// XDR variable-length opaque data: its length, the bytes, then padding.
fn xdr_opaque(data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(data.len()).unwrap();
    [
        words(&[length]),
        data.to_vec(),
        vec![0; xdr_padding(data.len())],
    ]
    .concat()
}

/// A sample or a record: its format, then its data.
fn formatted(format: u32, data: &[u8]) -> Vec<u8> {
    [words(&[format]), xdr_opaque(data)].concat()
}

fn datagram(samples: &[Vec<u8>]) -> Vec<u8> {
    // Version, IPv4 agent 192.0.2.1, sub-agent, sequence, uptime.
    let count = u32::try_from(samples.len()).unwrap();
    let header = words(&[5, 1, 0xc000_0201, 0, 1, 1000, count]);
    [header, samples.concat()].concat()
}

/// A flow sample stating `count` records, followed by `trailing` bytes.
fn flow_sample(count: u32, records: &[Vec<u8>], trailing: &[u8]) -> Vec<u8> {
    // Sequence, source ID, sampling rate, pool, drops, input, output.
    let fields = words(&[1, 3, 100, 100, 0, 3, 4, count]);
    formatted(1, &[fields, records.concat(), trailing.to_vec()].concat())
}

fn sampled_header(protocol: u32) -> Vec<u8> {
    // Protocol, frame length, stripped, then a 4-byte header.
    formatted(1, &words(&[protocol, 64, 4, 4, 0]))
}

fn counters_sample() -> Vec<u8> {
    // Sequence, source ID, no records.
    formatted(2, &words(&[1, 3, 0]))
}

fn samples(datagram: &[u8]) -> Vec<Sample> {
    parse(datagram).unwrap().samples
}

/// The only record of the only flow sample.
fn only_flow_record(datagram: &[u8]) -> FlowRecord {
    let samples = samples(datagram);
    let [Sample::Flow(sample)] = samples.as_slice() else {
        panic!("expected one flow sample");
    };
    let [record] = sample.records.as_slice() else {
        panic!("expected one record");
    };
    record.clone()
}

fn written(packet: &Packet) -> Vec<u8> {
    let mut buf = Vec::new();
    write(packet, &mut buf).unwrap();
    buf
}

/// Parses `datagram`, and checks it writes back unchanged.
fn round_trip(datagram: &[u8]) -> Packet {
    let packet = parse(datagram).unwrap();
    assert_eq!(written(&packet), datagram);
    packet
}

#[test]
fn real_datagrams_parse_and_write_back_unchanged() {
    let datagrams = udp_payloads("sflow_v5_sanity.pcap");
    assert_eq!(datagrams.len(), 3);
    for datagram in &datagrams {
        round_trip(datagram);
    }

    let packet = parse(&datagrams[0]).unwrap();
    assert_eq!(
        packet.header.agent_address,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    let Sample::Flow(sample) = &packet.samples[0] else {
        panic!("expected a flow sample");
    };
    assert_eq!(sample.sampling_rate, 2000);
    assert!(matches!(
        &sample.records[1],
        FlowRecord::SampledHeader(SampledHeader {
            protocol: HeaderProtocol::EthernetIso88023,
            frame_length: 1518,
            ..
        })
    ));
}

#[test]
fn another_version_is_rejected() {
    let mut datagram = datagram(&[]);
    datagram[..4].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(parse(&datagram), Err(ParseError::Version(4)));
}

#[test]
fn an_agent_address_of_an_unknown_type_fails_the_datagram() {
    let datagram = words(&[5, 3, 0, 0, 1, 1000, 0]);
    assert_eq!(parse(&datagram), Err(ParseError::AddressType(3)));
}

#[test]
fn unknown_addresses_are_none() {
    // An UNKNOWN agent address, and an extended router record with an
    // UNKNOWN next hop and masks 24 and 16.
    let router = formatted(1002, &words(&[0, 24, 16]));
    let sample = flow_sample(1, &[router], &[]);
    let datagram = [words(&[5, 0, 0, 1, 1000, 1]), sample].concat();

    let packet = round_trip(&datagram);

    assert_eq!(packet.header.agent_address, None);
    assert_eq!(
        only_flow_record(&datagram),
        FlowRecord::ExtendedRouter(ExtendedRouter {
            nexthop: None,
            src_mask_len: 24,
            dst_mask_len: 16,
        })
    );
}

#[test]
fn unknown_header_protocols_are_kept() {
    // Header protocol 15 is not one sFlow v5 assigns.
    let datagram = datagram(&[flow_sample(1, &[sampled_header(15)], &[])]);
    let FlowRecord::SampledHeader(header) = only_flow_record(&datagram) else {
        panic!("expected a sampled header");
    };
    assert_eq!(header.protocol, HeaderProtocol::Unassigned(15));
    round_trip(&datagram);
}

#[test]
fn a_record_that_does_not_parse_is_kept_as_bytes() {
    // An extended router whose next hop is of address type 9.
    let data = words(&[9, 24, 16]);
    let datagram = datagram(&[flow_sample(1, &[formatted(1002, &data)], &[])]);
    assert_eq!(
        only_flow_record(&datagram),
        FlowRecord::Unknown {
            format: DataFormat::standard(1002),
            data,
        }
    );
    round_trip(&datagram);
}

#[test]
fn a_sample_that_does_not_parse_is_kept_as_bytes() {
    // Two records stated, one present.
    let samples = samples(&datagram(&[
        flow_sample(2, &[sampled_header(1)], &[]),
        counters_sample(),
    ]));
    assert!(
        matches!(
            samples.as_slice(),
            [Sample::Unknown { .. }, Sample::Counters(_)]
        ),
        "{samples:?}"
    );
}

#[test]
fn bytes_past_a_samples_records_are_skipped() {
    let samples = samples(&datagram(&[
        flow_sample(1, &[sampled_header(1)], &[0; 8]),
        counters_sample(),
    ]));
    let [Sample::Flow(flow), Sample::Counters(_)] = samples.as_slice() else {
        panic!("expected a flow and a counters sample, got {samples:?}");
    };
    assert!(matches!(flow.records[0], FlowRecord::SampledHeader(_)));
}

#[test]
fn formats_of_other_enterprises_are_kept_as_bytes() {
    let vendor_format = (9 << 12) | 1;
    let record = formatted(vendor_format, &words(&[1, 2]));
    let sample = formatted(vendor_format, &words(&[3]));
    let datagram = datagram(&[flow_sample(1, &[record], &[]), sample]);

    let packet = round_trip(&datagram);

    let vendor = DataFormat {
        enterprise: 9,
        format: 1,
    };
    let Sample::Flow(flow) = &packet.samples[0] else {
        panic!("expected a flow sample");
    };
    assert_eq!(
        flow.records,
        [FlowRecord::Unknown {
            format: vendor,
            data: words(&[1, 2]),
        }]
    );
    assert_eq!(
        packet.samples[1],
        Sample::Unknown {
            format: vendor,
            data: words(&[3]),
        }
    );
}

#[test]
fn compact_source_ids_and_interfaces_split_into_their_parts() {
    // Source ID type 1, index 3; input of format 2 (2 interfaces); output
    // of format 0 with the "no interface" value.
    let fields = words(&[1, 0x0100_0003, 100, 100, 0, 0x8000_0002, 0x3fff_ffff, 0]);
    let datagram = datagram(&[formatted(1, &fields)]);

    let packet = round_trip(&datagram);

    let Sample::Flow(sample) = &packet.samples[0] else {
        panic!("expected a flow sample");
    };
    assert_eq!(
        sample.source_id,
        DataSource {
            source_id_type: 1,
            source_id_index: 3,
        }
    );
    assert_eq!(
        sample.input,
        Interface {
            format: 2,
            value: 2,
        }
    );
    assert_eq!(
        sample.output,
        Interface {
            format: 0,
            value: 0x3fff_ffff,
        }
    );
}

#[test]
fn expanded_samples_take_32_bits_for_each_part() {
    let flow = words(&[1, 0, 0x0100_0000, 100, 100, 0, 0, 5, 1, 258, 0]);
    let counters = words(&[1, 2, 0x0100_0000, 0]);
    let datagram = datagram(&[formatted(3, &flow), formatted(4, &counters)]);

    let packet = round_trip(&datagram);

    let [
        Sample::ExpandedFlow(flow),
        Sample::ExpandedCounters(counters),
    ] = packet.samples.as_slice()
    else {
        panic!("expected expanded samples, got {:?}", packet.samples);
    };
    assert_eq!(flow.source_id.source_id_index, 0x0100_0000);
    assert_eq!(
        flow.output,
        Interface {
            format: 1,
            value: 258,
        }
    );
    assert_eq!(counters.source_id.source_id_type, 2);
}

#[test]
fn discarded_packets_keep_unrecognized_reasons() {
    let discarded = |reason| formatted(5, &words(&[1, 0, 3, 0, 3, 0, reason, 0]));
    let datagram = datagram(&[discarded(258), discarded(500)]);

    let packet = round_trip(&datagram);

    let reasons: Vec<_> = packet
        .samples
        .iter()
        .map(|sample| match sample {
            Sample::Discarded(packet) => packet.reason,
            other => panic!("expected a discarded packet, got {other:?}"),
        })
        .collect();
    assert_eq!(reasons, [DropReason::Acl, DropReason::Unassigned(500)]);
}

#[test]
fn urls_carry_their_host_and_strings_are_padded() {
    let url = [words(&[2]), xdr_opaque(b"/index.html"), xdr_opaque(b"host")].concat();
    let datagram = datagram(&[flow_sample(1, &[formatted(1005, &url)], &[])]);

    round_trip(&datagram);

    assert_eq!(
        only_flow_record(&datagram),
        FlowRecord::ExtendedUrl(ExtendedUrl {
            direction: UrlDirection::Dst,
            url: "/index.html".to_owned(),
            host: "host".to_owned(),
        })
    );
}

#[test]
fn a_string_that_is_not_utf8_keeps_its_record_as_bytes() {
    let url = [words(&[1]), xdr_opaque(&[0xff, 0xfe]), xdr_opaque(b"")].concat();
    let datagram = datagram(&[flow_sample(1, &[formatted(1005, &url)], &[])]);
    assert!(matches!(
        only_flow_record(&datagram),
        FlowRecord::Unknown { .. }
    ));
}

#[test]
fn as_paths_keep_their_order() {
    // Next hop 203.0.113.1; AS 65000, source AS 64512, peer AS 64513; a set
    // of three ASes, then a sequence of two; one community; local pref 100.
    let gateway = words(&[
        1,
        0xcb00_7101,
        65000,
        64512,
        64513,
        2,
        1,
        3,
        30,
        10,
        20,
        2,
        2,
        100,
        200,
        1,
        0x0001_0002,
        100,
    ]);
    let datagram = datagram(&[flow_sample(1, &[formatted(1003, &gateway)], &[])]);

    round_trip(&datagram);

    let FlowRecord::ExtendedGateway(gateway) = only_flow_record(&datagram) else {
        panic!("expected an extended gateway");
    };
    assert_eq!(
        gateway.dst_as_path,
        [
            AsPathSegment::AsSet(vec![30, 10, 20]),
            AsPathSegment::AsSequence(vec![100, 200]),
        ]
    );
    assert_eq!(gateway.communities, [0x0001_0002]);
}

#[test]
fn data_formats_split_into_enterprise_and_format() {
    let format = DataFormat::from((9 << 12) | 1005);
    assert_eq!(
        format,
        DataFormat {
            enterprise: 9,
            format: 1005,
        }
    );
    assert_eq!(u32::try_from(format), Ok((9 << 12) | 1005));
}

#[test]
fn a_value_too_wide_for_its_field_writes_nothing() {
    let packet = parse(&datagram(&[flow_sample(0, &[], &[])])).unwrap();
    let with_sample = |sample| Packet {
        header: packet.header.clone(),
        samples: vec![sample],
    };
    let Sample::Flow(flow) = &packet.samples[0] else {
        panic!("expected a flow sample");
    };
    let mut wide_index = flow.clone();
    wide_index.source_id.source_id_index = 1 << 24;
    let mut wide_interface = flow.clone();
    wide_interface.input.format = 4;
    let vendor = DataFormat {
        enterprise: 1 << 20,
        format: 1,
    };

    for (sample, error) in [
        (
            Sample::Flow(wide_index),
            WriteError::TooLarge {
                field: "source ID index",
                value: 1 << 24,
            },
        ),
        (
            Sample::Flow(wide_interface),
            WriteError::TooLarge {
                field: "interface format",
                value: 4,
            },
        ),
        (
            Sample::Unknown {
                format: vendor,
                data: Vec::new(),
            },
            WriteError::TooLarge {
                field: "enterprise",
                value: 1 << 20,
            },
        ),
    ] {
        let mut buf = vec![0xaa];
        assert_eq!(write(&with_sample(sample), &mut buf), Err(error));
        assert_eq!(buf, [0xaa]);
    }
}

#[cfg(feature = "serde")]
#[test]
fn round_trips_through_serde() {
    let datagrams = udp_payloads("sflow_v5_sanity.pcap");
    let packet = parse(&datagrams[1]).unwrap();
    let json = serde_json::to_value(&packet).unwrap();
    assert_eq!(json["sequence_number"], 402);
    assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
}
