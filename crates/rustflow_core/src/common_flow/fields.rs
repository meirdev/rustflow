use std::net::IpAddr;

use jiff::Timestamp;

use super::CommonFlow;
use super::sampling::SamplingParams;
use crate::information_element::ElementId;
use crate::mac_address::MacAddress;
use crate::net::{ETHER_TYPE_IPV4, ETHER_TYPE_IPV6};
use crate::template::FieldSpecifier;
use crate::value::Value;

const NANOS_PER_MICRO: i64 = 1_000;
const NANOS_PER_MILLI: i64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
pub(super) struct ExportTime {
    time: Timestamp,
    time_ns: i64,
    uptime: Option<u32>,
}

impl ExportTime {
    pub(super) fn new(time: Timestamp, uptime: Option<u32>) -> Self {
        let time_ns = i64::try_from(time.as_nanosecond())
            .expect("a 32-bit Unix time fits in i64 nanoseconds");
        Self {
            time,
            time_ns,
            uptime,
        }
    }

    /// The Unix time, in nanoseconds, of an earlier uptime of the exporter,
    /// even when the 32-bit millisecond counter wrapped in between.
    pub(super) fn uptime_ns(&self, uptime: u32) -> Option<i64> {
        let before_export = self.uptime?.wrapping_sub(uptime);
        Some(self.time_ns - i64::from(before_export) * NANOS_PER_MILLI)
    }

    fn timestamp_ns(&self, value: &Value) -> Option<i64> {
        let time = value.to_timestamp_relative_to(self.time)?;
        i64::try_from(time.as_nanosecond()).ok()
    }

    fn delta_ns(&self, value: &Value) -> Option<i64> {
        let micros = i64::try_from(value.as_u64()?).ok()?;
        self.time_ns
            .checked_sub(micros.checked_mul(NANOS_PER_MICRO)?)
    }
}

pub(super) fn record_flow(
    mut flow: CommonFlow,
    export: &ExportTime,
    fields: &[FieldSpecifier],
    record: &[Value],
    sampling_rate: impl Fn(Option<u64>) -> Option<u32>,
) -> CommonFlow {
    let mut params = SamplingParams::default();
    for (field, value) in fields.iter().zip(record) {
        let id = field.element_id();
        params.observe(id, value);
        set_field(&mut flow, export, id, value);
    }
    flow.sampling_rate = params.rate().or_else(|| sampling_rate(params.sampler()));
    finish(&mut flow);
    flow
}

fn set_field(flow: &mut CommonFlow, export: &ExportTime, id: ElementId, value: &Value) {
    let number = value.as_u64();
    let address = ip_address(value);
    match id {
        ElementId::OCTET_DELTA_COUNT => set(&mut flow.bytes, number),
        ElementId::POST_OCTET_DELTA_COUNT
        | ElementId::OCTET_TOTAL_COUNT
        | ElementId::DATA_LINK_FRAME_SIZE => {
            fallback(&mut flow.bytes, number);
        }
        ElementId::PACKET_DELTA_COUNT => set(&mut flow.packets, number),
        ElementId::POST_PACKET_DELTA_COUNT | ElementId::PACKET_TOTAL_COUNT => {
            fallback(&mut flow.packets, number);
        }

        ElementId::SOURCE_IPV4_ADDRESS | ElementId::SOURCE_IPV6_ADDRESS => {
            set(&mut flow.src_addr, address);
        }
        ElementId::DESTINATION_IPV4_ADDRESS | ElementId::DESTINATION_IPV6_ADDRESS => {
            set(&mut flow.dst_addr, address);
        }
        ElementId::SOURCE_IPV4_PREFIX_LENGTH | ElementId::SOURCE_IPV6_PREFIX_LENGTH => {
            set(&mut flow.src_net, narrow(number));
        }
        ElementId::DESTINATION_IPV4_PREFIX_LENGTH | ElementId::DESTINATION_IPV6_PREFIX_LENGTH => {
            set(&mut flow.dst_net, narrow(number));
        }
        ElementId::IP_NEXT_HOP_IPV4_ADDRESS | ElementId::IP_NEXT_HOP_IPV6_ADDRESS => {
            set(&mut flow.next_hop, address);
        }
        ElementId::BGP_NEXT_HOP_IPV4_ADDRESS | ElementId::BGP_NEXT_HOP_IPV6_ADDRESS => {
            set(&mut flow.bgp_next_hop, address);
        }
        ElementId::SOURCE_MAC_ADDRESS => set(&mut flow.src_mac, mac_address(value)),
        ElementId::DESTINATION_MAC_ADDRESS => set(&mut flow.dst_mac, mac_address(value)),
        // NetFlow v9's OUT_SRC_MAC and DST_MAC, the outgoing frame's.
        ElementId::POST_SOURCE_MAC_ADDRESS => fallback(&mut flow.src_mac, mac_address(value)),
        ElementId::POST_DESTINATION_MAC_ADDRESS => {
            fallback(&mut flow.dst_mac, mac_address(value));
        }

        ElementId::ETHERNET_TYPE => set(&mut flow.etype, narrow(number)),
        ElementId::IP_VERSION => set(&mut flow.etype, number.and_then(ether_type)),
        ElementId::PROTOCOL_IDENTIFIER => set(&mut flow.proto, narrow(number)),
        ElementId::SOURCE_TRANSPORT_PORT => set(&mut flow.src_port, narrow(number)),
        ElementId::DESTINATION_TRANSPORT_PORT => set(&mut flow.dst_port, narrow(number)),
        ElementId::TCP_CONTROL_BITS => set(&mut flow.tcp_flags, narrow(number)),
        ElementId::IP_CLASS_OF_SERVICE => set(&mut flow.ip_tos, narrow(number)),
        ElementId::IP_TTL => set(&mut flow.ip_ttl, narrow(number)),
        ElementId::MINIMUM_TTL => fallback(&mut flow.ip_ttl, narrow(number)),
        ElementId::FLOW_LABEL_IPV6 => set(&mut flow.ipv6_flow_label, narrow(number)),
        ElementId::FRAGMENT_IDENTIFICATION => set(&mut flow.fragment_id, narrow(number)),
        ElementId::FRAGMENT_OFFSET => set(&mut flow.fragment_offset, narrow(number)),

        // Type in the high byte, code in the low one.
        ElementId::ICMP_TYPE_CODE_IPV4 | ElementId::ICMP_TYPE_CODE_IPV6 => {
            if let Some([icmp_type, icmp_code]) = narrow::<u16>(number).map(u16::to_be_bytes) {
                flow.icmp_type = Some(icmp_type);
                flow.icmp_code = Some(icmp_code);
            }
        }
        ElementId::ICMP_TYPE_IPV4 | ElementId::ICMP_TYPE_IPV6 => {
            set(&mut flow.icmp_type, narrow(number));
        }
        ElementId::ICMP_CODE_IPV4 | ElementId::ICMP_CODE_IPV6 => {
            set(&mut flow.icmp_code, narrow(number));
        }

        ElementId::INGRESS_INTERFACE => set(&mut flow.in_if, narrow(number)),
        ElementId::EGRESS_INTERFACE => set(&mut flow.out_if, narrow(number)),
        ElementId::BGP_SOURCE_AS_NUMBER => set(&mut flow.src_as, narrow(number)),
        ElementId::BGP_DESTINATION_AS_NUMBER => set(&mut flow.dst_as, narrow(number)),
        ElementId::VLAN_ID => set(&mut flow.src_vlan, narrow(number)),
        ElementId::POST_VLAN_ID => set(&mut flow.dst_vlan, narrow(number)),
        ElementId::FORWARDING_STATUS => set(&mut flow.forwarding_status, narrow(number)),

        ElementId::FLOW_START_SYS_UP_TIME => {
            let uptime = narrow(number).and_then(|uptime| export.uptime_ns(uptime));
            set(&mut flow.time_flow_start_ns, uptime);
        }
        ElementId::FLOW_END_SYS_UP_TIME => {
            let uptime = narrow(number).and_then(|uptime| export.uptime_ns(uptime));
            set(&mut flow.time_flow_end_ns, uptime);
        }
        ElementId::FLOW_START_SECONDS
        | ElementId::FLOW_START_MILLISECONDS
        | ElementId::FLOW_START_MICROSECONDS
        | ElementId::FLOW_START_NANOSECONDS => {
            set(&mut flow.time_flow_start_ns, export.timestamp_ns(value));
        }
        ElementId::FLOW_END_SECONDS
        | ElementId::FLOW_END_MILLISECONDS
        | ElementId::FLOW_END_MICROSECONDS
        | ElementId::FLOW_END_NANOSECONDS => {
            set(&mut flow.time_flow_end_ns, export.timestamp_ns(value));
        }
        ElementId::FLOW_START_DELTA_MICROSECONDS => {
            set(&mut flow.time_flow_start_ns, export.delta_ns(value));
        }
        ElementId::FLOW_END_DELTA_MICROSECONDS => {
            set(&mut flow.time_flow_end_ns, export.delta_ns(value));
        }

        _ => {}
    }
}

fn finish(flow: &mut CommonFlow) {
    if flow.etype.is_none() {
        flow.etype = flow
            .src_addr
            .or(flow.dst_addr)
            .map(|address| match address {
                IpAddr::V4(_) => ETHER_TYPE_IPV4,
                IpAddr::V6(_) => ETHER_TYPE_IPV6,
            });
    }
}

fn set<T>(field: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *field = value;
    }
}

fn fallback<T>(field: &mut Option<T>, value: Option<T>) {
    if field.is_none() {
        *field = value;
    }
}

fn narrow<T: TryFrom<u64>>(number: Option<u64>) -> Option<T> {
    T::try_from(number?).ok()
}

fn ip_address(value: &Value) -> Option<IpAddr> {
    match *value {
        Value::Ipv4Address(address) => Some(address.into()),
        Value::Ipv6Address(address) => Some(address.into()),
        _ => None,
    }
}

fn mac_address(value: &Value) -> Option<MacAddress> {
    match value {
        Value::MacAddress(address) => Some(*address),
        _ => None,
    }
}

fn ether_type(version: u64) -> Option<u16> {
    match version {
        4 => Some(ETHER_TYPE_IPV4),
        6 => Some(ETHER_TYPE_IPV6),
        _ => None,
    }
}
