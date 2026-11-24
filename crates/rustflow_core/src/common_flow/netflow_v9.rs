use std::net::IpAddr;
use std::time::Instant;

use super::fields::{ExportTime, record_flow};
use super::options::ExporterOptions;
use super::sets::{data_records, learn_options};
use super::{CommonFlow, FlowType};
use crate::information_element::ElementId;
use crate::net::ETHER_TYPE_IPV4;
use crate::netflow_v9::Packet;

pub fn from_netflow_v9<'a>(
    packet: &'a Packet,
    sampler_address: IpAddr,
    time_received_ns: i64,
    options: &'a mut ExporterOptions,
    now: Instant,
) -> impl Iterator<Item = CommonFlow> + 'a {
    let header = &packet.header;
    let domain = header.source_id;

    learn_options(&packet.flow_sets, domain, options, now);
    let options = &*options;

    let export = ExportTime::new(header.unix_time(), Some(header.sys_uptime));
    let flow = CommonFlow {
        observation_domain_id: Some(domain),
        ..CommonFlow::new(
            FlowType::NetflowV9,
            time_received_ns,
            sampler_address,
            header.sequence_number,
        )
    };
    data_records(&packet.flow_sets).map(move |(fields, record)| {
        let mut flow = record_flow(flow.clone(), &export, fields, record, |sampler| {
            options.sampling_rate(domain, sampler, now)
        });
        // "If not present in the template, then version 4 is assumed"
        // (RFC 3954 §8, IP_PROTOCOL_VERSION).
        if flow.etype.is_none()
            && !fields
                .iter()
                .any(|f| f.element_id() == ElementId::IP_VERSION)
        {
            flow.etype = Some(ETHER_TYPE_IPV4);
        }
        flow
    })
}
