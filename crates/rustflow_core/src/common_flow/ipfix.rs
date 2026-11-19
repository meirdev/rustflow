use std::net::IpAddr;
use std::time::Instant;

use super::fields::{ExportTime, record_flow};
use super::options::ExporterOptions;
use super::packet::dissect;
use super::sets::{data_records, learn_options};
use super::{CommonFlow, FlowType};
use crate::information_element::ElementId;
use crate::ipfix::Packet;
use crate::net::Protocol;
use crate::template::FieldSpecifier;
use crate::value::Value;

/// IEEE 802.3 Ethernet, as `dataLinkFrameType` names it.
const DATA_LINK_FRAME_TYPE_ETHERNET: u64 = 0x0001;

pub fn from_ipfix<'a>(
    packet: &'a Packet,
    sampler_address: IpAddr,
    time_received_ns: i64,
    options: &'a mut ExporterOptions,
    now: Instant,
) -> impl Iterator<Item = CommonFlow> + 'a {
    let header = &packet.header;
    let domain = header.observation_domain_id;

    learn_options(&packet.sets, domain, options, now);
    let options = &*options;

    let uptime = options
        .system_init_ms(domain, now)
        .and_then(|init_ms| uptime_at(header.export_time, init_ms));
    let export = ExportTime::new(header.unix_time(), uptime);
    let base = CommonFlow {
        observation_domain_id: Some(domain),
        ..CommonFlow::new(
            FlowType::Ipfix,
            time_received_ns,
            sampler_address,
            header.sequence_number,
        )
    };
    data_records(&packet.sets).map(move |(fields, record)| {
        // A PSAMP packet report carries the sampled packet's first octets.
        // Its headers go in first, so that the elements the record states
        // overwrite them, whatever their order in the template.
        let mut flow = base.clone();
        let section = packet_section(fields, record);
        if let Some((protocol, mut octets)) = section {
            // The octets are clipped; what was read before the end still
            // counts.
            dissect(&mut flow, protocol, &mut octets);
        }
        let mut flow = record_flow(flow, &export, fields, record, |sampler| {
            options.sampling_rate(domain, sampler, now)
        });
        if section.is_some() {
            // A packet report is about one packet.
            flow.packets.get_or_insert(1);
        }
        flow
    })
}

fn uptime_at(export_time: u32, init_ms: u64) -> Option<u32> {
    let uptime_ms = (u64::from(export_time) * 1_000).checked_sub(init_ms)?;
    Some(uptime_ms as u32) // modulo 2^32, as the counter wraps
}

fn packet_section<'a>(
    fields: &[FieldSpecifier],
    record: &'a [Value],
) -> Option<(Protocol, &'a [u8])> {
    let (mut frame, mut ip_header, mut frame_type) = (None, None, None);
    for (field, value) in fields.iter().zip(record) {
        match field.element_id() {
            ElementId::DATA_LINK_FRAME_SECTION => frame = octets(value),
            ElementId::IP_HEADER_PACKET_SECTION => ip_header = octets(value),
            ElementId::DATA_LINK_FRAME_TYPE => frame_type = value.as_u64(),
            ElementId::SECTION_OFFSET if value.as_u64() != Some(0) => return None,
            _ => {}
        }
    }
    if let Some(frame) = frame
        && frame_type.is_none_or(|frame_type| frame_type == DATA_LINK_FRAME_TYPE_ETHERNET)
    {
        return Some((Protocol::Ethernet, frame));
    }
    let ip_header = ip_header?;
    let protocol = match ip_header.first()? >> 4 {
        4 => Protocol::Ipv4,
        6 => Protocol::Ipv6,
        _ => return None,
    };
    Some((protocol, ip_header))
}

fn octets(value: &Value) -> Option<&[u8]> {
    match value {
        Value::OctetArray(octets) => Some(octets),
        _ => None,
    }
}
