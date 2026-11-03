//! NetFlow v5 flow records as IPFIX records: every record has the same
//! fields, each an IANA element of the same meaning.

use std::sync::Arc;

use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::netflow_v5::{FlowRecord, Packet};
use rustflow_protocol::value::Value;

use crate::record::Additions;
use crate::sampling::Sampling;
use crate::time::uptime_to_unix_millis;
use crate::{Protocol, Received, Record};

/// The element of each value [`record_values`] gives, in its order.
const ELEMENTS: [ElementId; 18] = [
    iana::SOURCE_IPV4_ADDRESS,
    iana::DESTINATION_IPV4_ADDRESS,
    iana::IP_NEXT_HOP_IPV4_ADDRESS,
    iana::INGRESS_INTERFACE,
    iana::EGRESS_INTERFACE,
    iana::PACKET_DELTA_COUNT,
    iana::OCTET_DELTA_COUNT,
    iana::FLOW_START_MILLISECONDS,
    iana::FLOW_END_MILLISECONDS,
    iana::SOURCE_TRANSPORT_PORT,
    iana::DESTINATION_TRANSPORT_PORT,
    iana::TCP_CONTROL_BITS,
    iana::PROTOCOL_IDENTIFIER,
    iana::IP_CLASS_OF_SERVICE,
    iana::BGP_SOURCE_AS_NUMBER,
    iana::BGP_DESTINATION_AS_NUMBER,
    iana::SOURCE_IPV4_PREFIX_LENGTH,
    iana::DESTINATION_IPV4_PREFIX_LENGTH,
];

/// Converts a NetFlow v5 packet's flow records, adding them to `records`.
///
/// The header's sampling interval is taken as one packet in that many, by
/// a method it does not say: its sampling mode bits are not interpreted. An
/// interval of 0, which unsampled exporters send, is one in one.
pub fn convert(packet: &Packet, received: &Received, records: &mut impl Extend<Record>) {
    let header = &packet.header;
    let export_time_ms =
        u64::from(header.unix_secs) * 1_000 + u64::from(header.unix_nsecs / 1_000_000);
    let millis = |uptime_ms| {
        uptime_to_unix_millis(export_time_ms, header.sys_uptime, uptime_ms)
            .map_or(Value::Null, Value::DateTimeMilliseconds)
    };

    let mut additions = Additions::new(received, None);
    additions.push(iana::ENGINE_TYPE, Value::Unsigned8(header.engine_type));
    additions.push(iana::ENGINE_ID, Value::Unsigned8(header.engine_id));
    Sampling {
        rate: u32::from(header.sampling_interval.interval).max(1),
        method: None,
    }
    .add_to(&mut additions);
    let elements: Arc<[ElementId]> = ELEMENTS.iter().copied().chain(additions.elements).collect();

    records.extend(packet.flow_records.iter().map(|record| {
        Record {
            protocol: Protocol::NetflowV5,
            sequence_number: header.flow_sequence,
            elements: Arc::clone(&elements),
            values: record_values(record, millis)
                .into_iter()
                .chain(additions.values.iter().cloned())
                .collect(),
        }
    }));
}

fn record_values(record: &FlowRecord, millis: impl Fn(u32) -> Value) -> [Value; 18] {
    let FlowRecord {
        srcaddr,
        dstaddr,
        nexthop,
        input,
        output,
        d_pkts,
        d_octets,
        first,
        last,
        srcport,
        dstport,
        tcp_flags,
        prot,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
    } = *record;
    [
        Value::Ipv4Address(srcaddr),
        Value::Ipv4Address(dstaddr),
        Value::Ipv4Address(nexthop),
        Value::Unsigned32(u32::from(input)),
        Value::Unsigned32(u32::from(output)),
        Value::Unsigned64(u64::from(d_pkts)),
        Value::Unsigned64(u64::from(d_octets)),
        millis(first),
        millis(last),
        Value::Unsigned16(srcport),
        Value::Unsigned16(dstport),
        Value::Unsigned16(u16::from(tcp_flags)),
        Value::Unsigned8(prot),
        Value::Unsigned8(tos),
        Value::Unsigned32(u32::from(src_as)),
        Value::Unsigned32(u32::from(dst_as)),
        Value::Unsigned8(src_mask),
        Value::Unsigned8(dst_mask),
    ]
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustflow_protocol::netflow_v5::{self, Header};

    use super::*;
    use crate::fixtures::udp_payloads;

    fn flow_record() -> FlowRecord {
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

    /// Exported at 1_700_000_000.5 s, an hour after the exporter booted.
    fn packet(interval: u16) -> Packet {
        Packet {
            header: Header {
                version: netflow_v5::VERSION,
                count: 2,
                sys_uptime: 3_600_000,
                unix_secs: 1_700_000_000,
                unix_nsecs: 500_000_000,
                flow_sequence: 42,
                engine_type: 1,
                engine_id: 2,
                sampling_interval: netflow_v5::Sampling { mode: 1, interval },
            },
            flow_records: vec![flow_record(), flow_record()],
        }
    }

    fn received_from(exporter: IpAddr, time: Option<SystemTime>) -> Received {
        Received { exporter, time }
    }

    fn converted(packet: &Packet, received: &Received) -> Vec<Record> {
        let mut records = Vec::new();
        convert(packet, received, &mut records);
        records
    }

    fn exporter() -> Received {
        received_from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)), None)
    }

    #[test]
    fn every_field_becomes_its_iana_element() {
        let records = converted(&packet(0), &exporter());
        let record = &records[0];
        for (element, value) in [
            (
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            (
                iana::IP_NEXT_HOP_IPV4_ADDRESS,
                Value::Ipv4Address(Ipv4Addr::new(203, 0, 113, 1)),
            ),
            (iana::INGRESS_INTERFACE, Value::Unsigned32(1)),
            (iana::PACKET_DELTA_COUNT, Value::Unsigned64(10)),
            (iana::OCTET_DELTA_COUNT, Value::Unsigned64(1500)),
            (iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(80)),
            (iana::TCP_CONTROL_BITS, Value::Unsigned16(0x18)),
            (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(6)),
            (iana::BGP_DESTINATION_AS_NUMBER, Value::Unsigned32(64501)),
            (iana::DESTINATION_IPV4_PREFIX_LENGTH, Value::Unsigned8(16)),
            (iana::ENGINE_TYPE, Value::Unsigned8(1)),
            (iana::ENGINE_ID, Value::Unsigned8(2)),
        ] {
            assert_eq!(record.first(element), Some(&value), "{element:?}");
        }
    }

    #[test]
    fn uptimes_become_absolute_times() {
        let records = converted(&packet(0), &exporter());
        // A minute, then a second, before the export time.
        assert_eq!(
            records[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_999_940_500))
        );
        assert_eq!(
            records[0].first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_999_999_500))
        );
        assert_eq!(records[0].first(iana::FLOW_START_SYS_UP_TIME), None);
    }

    #[test]
    fn the_records_of_a_packet_share_their_elements() {
        let records = converted(&packet(0), &exporter());
        assert_eq!(records.len(), 2);
        assert!(Arc::ptr_eq(&records[0].elements, &records[1].elements));
        assert_eq!(records[0].protocol, Protocol::NetflowV5);
        assert_eq!(records[0].sequence_number, 42);
    }

    #[test]
    fn the_exporter_and_receive_time_are_added() {
        let time = UNIX_EPOCH + Duration::from_millis(1_700_000_001_250);
        let ipv4 = converted(&packet(0), &received_from(exporter().exporter, Some(time)));
        assert_eq!(
            ipv4[0].first(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS),
            Some(&Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 254)))
        );
        assert_eq!(
            ipv4[0].first(iana::COLLECTION_TIME_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_700_000_001_250))
        );
        assert_eq!(ipv4[0].first(iana::ORIGINAL_OBSERVATION_DOMAIN_ID), None);

        let ipv6 = converted(
            &packet(0),
            &received_from(IpAddr::V6(Ipv6Addr::LOCALHOST), None),
        );
        assert_eq!(
            ipv6[0].first(iana::ORIGINAL_EXPORTER_IPV6_ADDRESS),
            Some(&Value::Ipv6Address(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(ipv6[0].first(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS), None);
        assert_eq!(ipv6[0].first(iana::COLLECTION_TIME_MILLISECONDS), None);
    }

    #[test]
    fn the_sampling_interval_is_one_in_that_many_by_an_unstated_method() {
        let space = |interval| {
            let records = converted(&packet(interval), &exporter());
            assert_eq!(
                records[0].first(iana::SAMPLING_PACKET_INTERVAL),
                Some(&Value::Unsigned32(1))
            );
            assert_eq!(records[0].first(iana::SELECTOR_ALGORITHM), None);
            records[0].first(iana::SAMPLING_PACKET_SPACE).cloned()
        };
        assert_eq!(space(100), Some(Value::Unsigned32(99)));
        assert_eq!(space(0), Some(Value::Unsigned32(0)));
    }

    #[test]
    fn real_packets_convert_every_flow_record() {
        for datagram in udp_payloads("netflow_v5_sanity.pcap") {
            let packet = netflow_v5::parse(&datagram).unwrap();
            let records = converted(&packet, &exporter());
            assert_eq!(records.len(), packet.flow_records.len());
            for record in &records {
                assert_eq!(record.values.len(), record.elements.len());
                assert!(matches!(
                    record.first(iana::FLOW_START_MILLISECONDS),
                    Some(Value::DateTimeMilliseconds(_))
                ));
            }
        }
    }
}
