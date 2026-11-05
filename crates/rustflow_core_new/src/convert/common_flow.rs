//! A flow as a fixed set of fields, for consumers that want those rather
//! than IPFIX elements: a view of a converted [`Record`], one mapping from
//! elements whatever protocol the record arrived in.

use std::fmt;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use macaddr::MacAddr6;

use crate::convert::record::Record;
use crate::convert::sampling::SamplingOptions;
use crate::protocol::Protocol;
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::value::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "SCREAMING_SNAKE_CASE")
)]
pub enum FlowType {
    #[default]
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

impl FlowType {
    /// The lowercase name, such as `netflow_v9`, that logs and metric labels
    /// use.
    pub fn name(self) -> &'static str {
        match self {
            Self::NetflowV5 => "netflow_v5",
            Self::NetflowV9 => "netflow_v9",
            Self::Ipfix => "ipfix",
            Self::SflowV5 => "sflow_v5",
        }
    }
}

/// The name in capitals, such as `NETFLOW_V9`, as it is serialized.
impl fmt::Display for FlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NetflowV5 => "NETFLOW_V5",
            Self::NetflowV9 => "NETFLOW_V9",
            Self::Ipfix => "IPFIX",
            Self::SflowV5 => "SFLOW_V5",
        })
    }
}

impl From<Protocol> for FlowType {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::NetflowV5 => Self::NetflowV5,
            Protocol::NetflowV9 => Self::NetflowV9,
            Protocol::Ipfix => Self::Ipfix,
            Protocol::SflowV5 => Self::SflowV5,
        }
    }
}

/// Calls `$callback!` with every field of
/// [`CommonFlow`](crate::convert::CommonFlow): its name, its kind, and
/// whether it is `required` or `optional`, for code written once per field.
#[macro_export]
macro_rules! for_each_flow_field {
    ($callback:ident) => {
        $callback! {
            flow_type: FlowType required,
            time_received_ns: Timestamp required,
            sequence_num: U32 required,
            sampling_rate: U32 optional,
            sampler_address: Ip optional,
            time_flow_start_ns: Timestamp optional,
            time_flow_end_ns: Timestamp optional,
            bytes: U64 optional,
            packets: U64 optional,
            src_addr: Ip optional,
            dst_addr: Ip optional,
            src_mac: Mac optional,
            dst_mac: Mac optional,
            etype: U16 optional,
            proto: U8 optional,
            src_port: U16 optional,
            dst_port: U16 optional,
            in_if: U32 optional,
            out_if: U32 optional,
            ip_tos: U8 optional,
            ip_ttl: U8 optional,
            tcp_flags: U16 optional,
            icmp_type: U8 optional,
            icmp_code: U8 optional,
            ipv6_flow_label: U32 optional,
            fragment_id: U32 optional,
            fragment_offset: U16 optional,
            src_as: U32 optional,
            dst_as: U32 optional,
            next_hop: Ip optional,
            src_net: U8 optional,
            dst_net: U8 optional,
            bgp_next_hop: Ip optional,
            src_vlan: U16 optional,
            dst_vlan: U16 optional,
            observation_domain_id: U32 optional,
            template_id: U16 optional,
            forwarding_status: U32 optional,
        }
    };
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CommonFlow {
    pub flow_type: FlowType,
    /// Nanoseconds since 1970.
    pub time_received_ns: i64,
    pub sequence_num: u32,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sampling_rate: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sampler_address: Option<IpAddr>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub time_flow_start_ns: Option<i64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub time_flow_end_ns: Option<i64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub bytes: Option<u64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub packets: Option<u64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub src_addr: Option<IpAddr>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dst_addr: Option<IpAddr>,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", serialize_with = "mac_text")
    )]
    pub src_mac: Option<MacAddr6>,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", serialize_with = "mac_text")
    )]
    pub dst_mac: Option<MacAddr6>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub etype: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub proto: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub src_port: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dst_port: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub in_if: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub out_if: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ip_tos: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ip_ttl: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tcp_flags: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub icmp_type: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub icmp_code: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ipv6_flow_label: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub fragment_id: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub fragment_offset: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub src_as: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dst_as: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub next_hop: Option<IpAddr>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub src_net: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dst_net: Option<u8>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub bgp_next_hop: Option<IpAddr>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub src_vlan: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dst_vlan: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub observation_domain_id: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub template_id: Option<u16>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub forwarding_status: Option<u32>,
}

impl CommonFlow {
    pub fn new(flow_type: FlowType) -> Self {
        Self {
            flow_type,
            ..Default::default()
        }
    }

    /// Sets the receive time. Nanoseconds in an `i64` reach from 1677 to
    /// 2262; a time beyond is held at the nearer end.
    pub fn with_time_received(mut self, time: SystemTime) -> Self {
        self.time_received_ns = unix_nanos(time);
        self
    }
}

/// A flow's fields, from the elements a converted record holds. Where a
/// field has several elements to come from, the first one the record has
/// gives it; a value too large for its field leaves it unset.
impl From<&Record> for CommonFlow {
    fn from(record: &Record) -> Self {
        // Readers always give a receive time; a record converted without
        // one is taken as received now.
        let time_received_ns = record
            .first(iana::COLLECTION_TIME_MILLISECONDS)
            .and_then(|time| i64::try_from(time.unix_nanos(0)?).ok())
            .unwrap_or_else(|| unix_nanos(SystemTime::now()));
        // Seconds and NTP timestamps wrap; the era nearest the receive time
        // is theirs.
        let reference = time_received_ns.div_euclid(1_000_000_000);
        let src_addr = address(record, iana::SOURCE_IPV4_ADDRESS, iana::SOURCE_IPV6_ADDRESS);
        let etype = unsigned(record, &[iana::ETHERNET_TYPE]).or(match src_addr {
            Some(IpAddr::V4(_)) => Some(0x0800),
            Some(IpAddr::V6(_)) => Some(0x86dd),
            None => None,
        });
        let icmp = unsigned::<u16>(
            record,
            &[iana::ICMP_TYPE_CODE_IPV4, iana::ICMP_TYPE_CODE_IPV6],
        )
        .map(u16::to_be_bytes);

        Self {
            flow_type: record.protocol.into(),
            time_received_ns,
            sequence_num: record.sequence_number,
            sampling_rate: sampling_rate(record),
            sampler_address: address(
                record,
                iana::EXPORTER_IPV4_ADDRESS,
                iana::EXPORTER_IPV6_ADDRESS,
            )
            .or(address(
                record,
                iana::ORIGINAL_EXPORTER_IPV4_ADDRESS,
                iana::ORIGINAL_EXPORTER_IPV6_ADDRESS,
            )),
            time_flow_start_ns: time_ns(
                record,
                &[
                    iana::FLOW_START_MILLISECONDS,
                    iana::FLOW_START_SECONDS,
                    iana::FLOW_START_MICROSECONDS,
                    iana::FLOW_START_NANOSECONDS,
                ],
                reference,
            ),
            time_flow_end_ns: time_ns(
                record,
                &[
                    iana::FLOW_END_MILLISECONDS,
                    iana::FLOW_END_SECONDS,
                    iana::FLOW_END_MICROSECONDS,
                    iana::FLOW_END_NANOSECONDS,
                ],
                reference,
            ),
            bytes: unsigned(
                record,
                &[
                    iana::OCTET_DELTA_COUNT,
                    iana::LAYER2_OCTET_DELTA_COUNT,
                    iana::DATA_LINK_FRAME_SIZE,
                ],
            ),
            packets: unsigned(record, &[iana::PACKET_DELTA_COUNT]),
            src_addr,
            dst_addr: address(
                record,
                iana::DESTINATION_IPV4_ADDRESS,
                iana::DESTINATION_IPV6_ADDRESS,
            ),
            src_mac: mac(
                record,
                &[iana::SOURCE_MAC_ADDRESS, iana::POST_SOURCE_MAC_ADDRESS],
            ),
            dst_mac: mac(
                record,
                &[
                    iana::DESTINATION_MAC_ADDRESS,
                    iana::POST_DESTINATION_MAC_ADDRESS,
                ],
            ),
            etype,
            proto: unsigned(record, &[iana::PROTOCOL_IDENTIFIER]),
            src_port: unsigned(record, &[iana::SOURCE_TRANSPORT_PORT]),
            dst_port: unsigned(record, &[iana::DESTINATION_TRANSPORT_PORT]),
            in_if: unsigned(record, &[iana::INGRESS_INTERFACE]),
            out_if: unsigned(record, &[iana::EGRESS_INTERFACE]),
            ip_tos: unsigned(record, &[iana::IP_CLASS_OF_SERVICE]),
            ip_ttl: unsigned(
                record,
                &[iana::IP_TTL, iana::MINIMUM_TTL, iana::MAXIMUM_TTL],
            ),
            tcp_flags: unsigned(record, &[iana::TCP_CONTROL_BITS]),
            icmp_type: unsigned(record, &[iana::ICMP_TYPE_IPV4, iana::ICMP_TYPE_IPV6])
                .or(icmp.map(|[icmp_type, _]| icmp_type)),
            icmp_code: unsigned(record, &[iana::ICMP_CODE_IPV4, iana::ICMP_CODE_IPV6])
                .or(icmp.map(|[_, icmp_code]| icmp_code)),
            ipv6_flow_label: unsigned(record, &[iana::FLOW_LABEL_IPV6]),
            fragment_id: unsigned(record, &[iana::FRAGMENT_IDENTIFICATION]),
            fragment_offset: unsigned(record, &[iana::FRAGMENT_OFFSET]),
            src_as: unsigned(record, &[iana::BGP_SOURCE_AS_NUMBER]),
            dst_as: unsigned(record, &[iana::BGP_DESTINATION_AS_NUMBER]),
            next_hop: address(
                record,
                iana::IP_NEXT_HOP_IPV4_ADDRESS,
                iana::IP_NEXT_HOP_IPV6_ADDRESS,
            ),
            src_net: unsigned(
                record,
                &[
                    iana::SOURCE_IPV4_PREFIX_LENGTH,
                    iana::SOURCE_IPV6_PREFIX_LENGTH,
                ],
            ),
            dst_net: unsigned(
                record,
                &[
                    iana::DESTINATION_IPV4_PREFIX_LENGTH,
                    iana::DESTINATION_IPV6_PREFIX_LENGTH,
                ],
            ),
            bgp_next_hop: address(
                record,
                iana::BGP_NEXT_HOP_IPV4_ADDRESS,
                iana::BGP_NEXT_HOP_IPV6_ADDRESS,
            ),
            // A frame's inner tag when it has two, as the customer's VLAN.
            src_vlan: unsigned(
                record,
                &[
                    iana::VLAN_ID,
                    iana::DOT1Q_CUSTOMER_VLAN_ID,
                    iana::DOT1Q_VLAN_ID,
                ],
            ),
            dst_vlan: unsigned(record, &[iana::POST_VLAN_ID]),
            observation_domain_id: unsigned(record, &[iana::ORIGINAL_OBSERVATION_DOMAIN_ID]),
            template_id: unsigned(record, &[iana::TEMPLATE_ID]),
            forwarding_status: unsigned(record, &[iana::FORWARDING_STATUS]),
        }
    }
}

fn unix_nanos(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_nanos()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_nanos()).map_or(i64::MIN, |nanos| -nanos),
    }
}

fn sampling_rate(record: &Record) -> Option<u32> {
    let mut options = SamplingOptions::default();
    for (element, value) in record.iter() {
        options.observe(element, value);
    }
    options.sampling().map(|sampling| sampling.rate)
}

fn first<'a>(record: &'a Record, elements: &[ElementId]) -> Option<&'a Value> {
    elements.iter().find_map(|&element| record.first(element))
}

fn unsigned<T: TryFrom<u64>>(record: &Record, elements: &[ElementId]) -> Option<T> {
    first(record, elements)?.as_u64()?.try_into().ok()
}

fn address(record: &Record, ipv4: ElementId, ipv6: ElementId) -> Option<IpAddr> {
    match *first(record, &[ipv4, ipv6])? {
        Value::Ipv4Address(address) => Some(address.into()),
        Value::Ipv6Address(address) => Some(address.into()),
        _ => None,
    }
}

fn mac(record: &Record, elements: &[ElementId]) -> Option<MacAddr6> {
    match *first(record, elements)? {
        Value::MacAddress(mac) => Some(mac.into()),
        _ => None,
    }
}

fn time_ns(record: &Record, elements: &[ElementId], reference: i64) -> Option<i64> {
    i64::try_from(first(record, elements)?.unix_nanos(reference)?).ok()
}

#[cfg(feature = "serde")]
fn mac_text<S: serde::Serializer>(
    mac: &Option<MacAddr6>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match mac {
        Some(mac) => serializer.collect_str(mac),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    macro_rules! names {
        ($( $name:ident : $kind:ident $presence:ident ),* $(,)?) => {
            /// Compiles only while the list and the struct name the same
            /// fields.
            fn names(flow: &CommonFlow) -> Vec<&'static str> {
                let CommonFlow { $( $name, )* } = flow;
                $( let _ = $name; )*
                vec![$( stringify!($name), )*]
            }
        };
    }
    for_each_flow_field!(names);

    #[test]
    fn the_field_list_names_every_field_of_the_struct() {
        let names = names(&CommonFlow::new(FlowType::Ipfix));
        assert_eq!(names.len(), 38);
        assert_eq!(names[0], "flow_type");
        assert_eq!(names[37], "forwarding_status");
    }

    #[test]
    fn a_receive_time_beyond_i64_nanoseconds_is_held_at_the_nearer_end() {
        let received = |time| {
            CommonFlow::new(FlowType::Ipfix)
                .with_time_received(time)
                .time_received_ns
        };
        let seconds = Duration::from_secs;
        assert_eq!(
            received(UNIX_EPOCH + seconds(1_700_000_000)),
            1_700_000_000_000_000_000
        );
        assert_eq!(received(UNIX_EPOCH - seconds(1)), -1_000_000_000);
        assert_eq!(
            received(UNIX_EPOCH + seconds(u64::from(u32::MAX) * 3)),
            i64::MAX
        );
    }

    fn record(protocol: Protocol, fields: &[(ElementId, Value)]) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Record {
            protocol,
            sequence_number: 7,
            scope: Vec::new(),
            elements: Arc::from(elements),
            values,
        }
    }

    #[test]
    fn the_first_element_a_field_can_come_from_gives_it() {
        let flow = CommonFlow::from(&record(
            Protocol::SflowV5,
            &[
                (iana::LAYER2_OCTET_DELTA_COUNT, Value::Unsigned64(1518)),
                (iana::DOT1Q_VLAN_ID, Value::Unsigned16(100)),
                (iana::DOT1Q_CUSTOMER_VLAN_ID, Value::Unsigned16(20)),
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    Value::Ipv4Address(Ipv4Addr::LOCALHOST),
                ),
                (
                    iana::ORIGINAL_EXPORTER_IPV4_ADDRESS,
                    Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 254)),
                ),
                (
                    iana::EXPORTER_IPV4_ADDRESS,
                    Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 10)),
                ),
            ],
        ));

        assert_eq!(flow.flow_type, FlowType::SflowV5);
        assert_eq!(flow.sequence_num, 7);
        assert_eq!(flow.bytes, Some(1518));
        assert_eq!(flow.src_vlan, Some(20));
        assert_eq!(flow.etype, Some(0x0800));
        assert_eq!(flow.sampler_address, Some(IpAddr::from([192, 0, 2, 10])));
    }

    #[test]
    fn times_sampling_and_icmp_are_read_from_their_elements() {
        let flow = CommonFlow::from(&record(
            Protocol::Ipfix,
            &[
                (
                    iana::COLLECTION_TIME_MILLISECONDS,
                    Value::DateTimeMilliseconds(1_700_000_000_500),
                ),
                (
                    iana::FLOW_START_SECONDS,
                    Value::DateTimeSeconds(1_699_999_990),
                ),
                (
                    iana::FLOW_END_MILLISECONDS,
                    Value::DateTimeMilliseconds(1_699_999_999_250),
                ),
                (iana::SAMPLING_SIZE, Value::Unsigned32(1)),
                (iana::SAMPLING_POPULATION, Value::Unsigned32(1000)),
                (iana::ICMP_TYPE_CODE_IPV4, Value::Unsigned16(0x0301)),
                (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(1)),
            ],
        ));

        assert_eq!(flow.time_received_ns, 1_700_000_000_500_000_000);
        assert_eq!(flow.time_flow_start_ns, Some(1_699_999_990_000_000_000));
        assert_eq!(flow.time_flow_end_ns, Some(1_699_999_999_250_000_000));
        assert_eq!(flow.sampling_rate, Some(1000));
        assert_eq!((flow.icmp_type, flow.icmp_code), (Some(3), Some(1)));
        assert_eq!(flow.etype, None);
    }

    #[test]
    fn a_value_too_large_for_its_field_leaves_it_unset() {
        let flow = CommonFlow::from(&record(
            Protocol::NetflowV9,
            &[(iana::SOURCE_TRANSPORT_PORT, Value::Unsigned32(70_000))],
        ));
        assert_eq!(flow.src_port, None);
    }

    #[test]
    fn a_record_without_a_collection_time_is_received_now() {
        let before = unix_nanos(SystemTime::now());
        let flow = CommonFlow::from(&record(Protocol::Ipfix, &[]));
        let after = unix_nanos(SystemTime::now());
        assert!((before..=after).contains(&flow.time_received_ns));
    }

    #[test]
    fn a_record_without_counters_leaves_them_unset_not_zero() {
        let flow = CommonFlow::from(&record(
            Protocol::Ipfix,
            &[(iana::PACKET_DELTA_COUNT, Value::Unsigned64(0))],
        ));
        assert_eq!((flow.bytes, flow.packets), (None, Some(0)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_as_before_unset_fields_left_out() {
        let flow = CommonFlow {
            src_mac: Some([2, 0, 0, 0, 1, 0xaa].into()),
            ..CommonFlow::new(FlowType::SflowV5)
        };
        assert_eq!(
            serde_json::to_value(&flow).unwrap(),
            serde_json::json!({
                "flow_type": "SFLOW_V5",
                "time_received_ns": 0,
                "sequence_num": 0,
                "src_mac": "02:00:00:00:01:AA",
            })
        );
        assert_eq!(FlowType::SflowV5.to_string(), "SFLOW_V5");
    }
}
