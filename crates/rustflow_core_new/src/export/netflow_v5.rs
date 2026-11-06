//! Records exported as NetFlow v5 packets.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::convert::Record;
use crate::export::{ExportError, unix_millis, uptime};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::netflow_v5::{FlowRecord, Header, Packet, Sampling, VERSION};
use crate::protocol::value::Value;

/// The AS number sent in place of one that does not fit 16 bits (RFC 6793
/// section 9).
const AS_TRANS: u16 = 23456;

/// Exports records as NetFlow v5 packets.
///
/// Each record fills the fixed-format flow record from the elements that
/// have a field in it; the rest are left out. A record needs an IPv4
/// source and destination. Counters and interface numbers that do not fit
/// their field saturate, a 4-byte AS number goes as `AS_TRANS`, and
/// absolute flow times go as uptimes relative to when the exporter booted.
/// A packet holds up to 30 records; the caller chooses how many.
#[derive(Debug)]
pub struct Exporter {
    boot_ms: u64,
    engine_type: u8,
    engine_id: u8,
    sampling: Sampling,
    /// Flows sent so far, modulo 2^32.
    flow_sequence: u32,
}

impl Exporter {
    pub fn new(boot: SystemTime) -> Self {
        Self {
            boot_ms: unix_millis(boot),
            engine_type: 0,
            engine_id: 0,
            sampling: Sampling {
                mode: 0,
                interval: 0,
            },
            flow_sequence: 0,
        }
    }

    pub fn with_engine(mut self, engine_type: u8, engine_id: u8) -> Self {
        self.engine_type = engine_type;
        self.engine_id = engine_id;
        self
    }

    /// The sampling the header states: one packet in `interval`, by
    /// `mode`.
    pub fn with_sampling(mut self, sampling: Sampling) -> Self {
        self.sampling = sampling;
        self
    }

    /// A packet of `records`, exported at `now`.
    pub fn export(&mut self, records: &[Record], now: SystemTime) -> Result<Packet, ExportError> {
        let export_ms = unix_millis(now);
        let sys_uptime = uptime(export_ms, self.boot_ms);
        let flow_records = records
            .iter()
            .map(|record| flow_record(record, self.boot_ms, sys_uptime))
            .collect::<Result<Vec<_>, _>>()?;
        let header = Header {
            version: VERSION,
            count: 0,
            sys_uptime,
            unix_secs: (export_ms / 1_000) as u32,
            unix_nsecs: (export_ms % 1_000 * 1_000_000) as u32,
            flow_sequence: self.flow_sequence,
            engine_type: self.engine_type,
            engine_id: self.engine_id,
            sampling_interval: self.sampling,
        };
        self.flow_sequence = self
            .flow_sequence
            .wrapping_add(u32::try_from(records.len()).unwrap_or(u32::MAX));
        Ok(Packet {
            header,
            flow_records,
        })
    }
}

fn flow_record(record: &Record, boot_ms: u64, sys_uptime: u32) -> Result<FlowRecord, ExportError> {
    let ipv4 = |element| match record.first(element) {
        Some(Value::Ipv4Address(address)) => Some(*address),
        _ => None,
    };
    let number = |element: ElementId| record.first(element).and_then(Value::as_u64);
    let unsigned32 = |element| number(element).map_or(0, |n| saturated(n, u32::MAX));
    let unsigned16 = |element| number(element).map_or(0, |n| saturated(n, u16::MAX));
    let unsigned8 = |element| number(element).map_or(0, |n| saturated(n, u8::MAX));
    let as_number = |element| number(element).map_or(0, |n| saturated(n, AS_TRANS));
    let time = |element| match record.first(element) {
        Some(Value::DateTimeMilliseconds(ms)) => uptime(*ms, boot_ms),
        _ => sys_uptime,
    };
    // The low eight bits: the NS flag has no place in the field.
    let tcp_flags = number(iana::TCP_CONTROL_BITS).map_or(0, |flags| (flags & 0xff) as u8);
    Ok(FlowRecord {
        srcaddr: ipv4(iana::SOURCE_IPV4_ADDRESS)
            .ok_or(ExportError::Missing(iana::SOURCE_IPV4_ADDRESS))?,
        dstaddr: ipv4(iana::DESTINATION_IPV4_ADDRESS)
            .ok_or(ExportError::Missing(iana::DESTINATION_IPV4_ADDRESS))?,
        nexthop: ipv4(iana::IP_NEXT_HOP_IPV4_ADDRESS).unwrap_or(Ipv4Addr::UNSPECIFIED),
        input: unsigned16(iana::INGRESS_INTERFACE),
        output: unsigned16(iana::EGRESS_INTERFACE),
        d_pkts: unsigned32(iana::PACKET_DELTA_COUNT),
        d_octets: unsigned32(iana::OCTET_DELTA_COUNT),
        first: time(iana::FLOW_START_MILLISECONDS),
        last: time(iana::FLOW_END_MILLISECONDS),
        srcport: unsigned16(iana::SOURCE_TRANSPORT_PORT),
        dstport: unsigned16(iana::DESTINATION_TRANSPORT_PORT),
        tcp_flags,
        prot: unsigned8(iana::PROTOCOL_IDENTIFIER),
        tos: unsigned8(iana::IP_CLASS_OF_SERVICE),
        src_as: as_number(iana::BGP_SOURCE_AS_NUMBER),
        dst_as: as_number(iana::BGP_DESTINATION_AS_NUMBER),
        src_mask: unsigned8(iana::SOURCE_IPV4_PREFIX_LENGTH),
        dst_mask: unsigned8(iana::DESTINATION_IPV4_PREFIX_LENGTH),
    })
}

/// `n` in a narrower type, or `instead` when it does not fit.
fn saturated<T: TryFrom<u64>>(n: u64, instead: T) -> T {
    T::try_from(n).unwrap_or(instead)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::convert::{self, Elements, Protocol, Received};
    use crate::protocol::netflow_v5;

    const BOOT_MS: u64 = 1_700_000_000_000;
    const START_MS: u64 = BOOT_MS + 90_000;
    const END_MS: u64 = BOOT_MS + 95_500;

    fn at_ms(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    fn record(fields: &[(ElementId, Value)]) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::new(Elements::from(elements)),
            values,
        }
    }

    fn flow() -> Record {
        record(&[
            (
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 1].into()),
            ),
            (
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 2].into()),
            ),
            (
                iana::IP_NEXT_HOP_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 3].into()),
            ),
            (iana::INGRESS_INTERFACE, Value::Unsigned32(1)),
            (iana::EGRESS_INTERFACE, Value::Unsigned32(2)),
            (iana::PACKET_DELTA_COUNT, Value::Unsigned64(10)),
            (iana::OCTET_DELTA_COUNT, Value::Unsigned64(1500)),
            (
                iana::FLOW_START_MILLISECONDS,
                Value::DateTimeMilliseconds(START_MS),
            ),
            (
                iana::FLOW_END_MILLISECONDS,
                Value::DateTimeMilliseconds(END_MS),
            ),
            (iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(1234)),
            (iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(80)),
            (iana::TCP_CONTROL_BITS, Value::Unsigned16(0x118)),
            (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(6)),
            (iana::IP_CLASS_OF_SERVICE, Value::Unsigned8(0x10)),
            (iana::BGP_SOURCE_AS_NUMBER, Value::Unsigned32(64496)),
            (
                iana::BGP_DESTINATION_AS_NUMBER,
                Value::Unsigned32(4_200_000_000),
            ),
            (iana::SOURCE_IPV4_PREFIX_LENGTH, Value::Unsigned8(24)),
            (iana::DESTINATION_IPV4_PREFIX_LENGTH, Value::Unsigned8(16)),
            (iana::INTERFACE_NAME, Value::String("eth0".into())),
        ])
    }

    #[test]
    fn records_come_back_through_a_collector_as_they_went() {
        let mut exporter = Exporter::new(at_ms(BOOT_MS))
            .with_engine(1, 2)
            .with_sampling(Sampling {
                mode: 1,
                interval: 100,
            });
        let now = at_ms(BOOT_MS + 100_000 + 250);
        let packet = exporter.export(&[flow(), flow()], now).unwrap();
        assert_eq!(packet.header.sys_uptime, 100_250);
        assert_eq!(packet.header.unix_secs, 1_700_000_100);
        assert_eq!(packet.header.unix_nsecs, 250_000_000);
        assert_eq!(packet.header.flow_sequence, 0);
        assert_eq!(
            packet.flow_records[0].tcp_flags, 0x18,
            "the NS flag dropped"
        );
        assert_eq!(packet.flow_records[0].dst_as, AS_TRANS);

        let mut buf = Vec::new();
        netflow_v5::write(&packet, &mut buf).unwrap();
        let parsed = netflow_v5::parse(&buf).unwrap();
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 2055)),
            time: None,
        };
        let mut records = Vec::new();
        convert::netflow_v5::convert(parsed, &received, &mut records);
        assert_eq!(records.len(), 2);
        let sent = flow();
        let back = &records[0];
        for (element, value) in sent.iter() {
            match element {
                iana::TCP_CONTROL_BITS => {
                    assert_eq!(back.first(element), Some(&Value::Unsigned16(0x18)));
                }
                iana::BGP_DESTINATION_AS_NUMBER => {
                    assert_eq!(back.first(element), Some(&Value::Unsigned32(23456)));
                }
                iana::INTERFACE_NAME => assert_eq!(back.first(element), None),
                _ => assert_eq!(back.first(element), Some(value), "{element}"),
            }
        }
        assert_eq!(back.first(iana::ENGINE_ID), Some(&Value::Unsigned8(2)));
        assert_eq!(
            back.first(iana::SAMPLING_PACKET_SPACE),
            Some(&Value::Unsigned32(99)),
            "one packet in 100"
        );

        let next = exporter.export(&[flow()], now).unwrap();
        assert_eq!(next.header.flow_sequence, 2, "flows are counted");
    }

    #[test]
    fn a_record_without_ipv4_addresses_cannot_be_sent() {
        let mut exporter = Exporter::new(at_ms(BOOT_MS));
        let ipv6 = record(&[
            (
                iana::SOURCE_IPV6_ADDRESS,
                Value::Ipv6Address([1; 16].into()),
            ),
            (
                iana::DESTINATION_IPV6_ADDRESS,
                Value::Ipv6Address([2; 16].into()),
            ),
        ]);
        assert_eq!(
            exporter.export(&[ipv6], at_ms(BOOT_MS)),
            Err(ExportError::Missing(iana::SOURCE_IPV4_ADDRESS))
        );
    }

    #[test]
    fn what_a_record_lacks_is_zero_and_its_times_now() {
        let mut exporter = Exporter::new(at_ms(BOOT_MS));
        let bare = record(&[
            (
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 1].into()),
            ),
            (
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 2].into()),
            ),
        ]);
        let packet = exporter.export(&[bare], at_ms(BOOT_MS + 5_000)).unwrap();
        let record = &packet.flow_records[0];
        assert_eq!(record.nexthop, Ipv4Addr::UNSPECIFIED);
        assert_eq!((record.first, record.last), (5_000, 5_000));
        assert_eq!((record.d_pkts, record.d_octets, record.prot), (0, 0, 0));
    }
}
