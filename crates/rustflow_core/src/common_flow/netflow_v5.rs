use std::net::IpAddr;

use super::fields::ExportTime;
use super::{CommonFlow, FlowType};
use crate::net::{ETHER_TYPE_IPV4, IP_PROTOCOL_ICMP};
use crate::netflow_v5::{FlowRecord, Header, Packet};

pub fn from_netflow_v5(
    packet: &Packet,
    sampler_address: IpAddr,
    time_received_ns: i64,
) -> impl Iterator<Item = CommonFlow> + '_ {
    let header = &packet.header;
    let export = ExportTime::new(header.unix_time(), Some(header.sys_uptime));
    packet
        .flow_records
        .iter()
        .map(move |record| flow(header, &export, record, sampler_address, time_received_ns))
}

fn flow(
    header: &Header,
    export: &ExportTime,
    record: &FlowRecord,
    sampler_address: IpAddr,
    time_received_ns: i64,
) -> CommonFlow {
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

    // ICMP flows carry the type and code in the destination port, type in the
    // high byte: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/flowmonitoring-output-formats-version5-solutions.html
    let (ports, icmp) = if prot == IP_PROTOCOL_ICMP {
        (None, Some(dstport.to_be_bytes()))
    } else {
        (Some((srcport, dstport)), None)
    };
    let interval = header.sampling_interval.interval;

    CommonFlow {
        sampling_rate: (interval != 0).then_some(interval.into()),
        time_flow_start_ns: export.uptime_ns(first),
        time_flow_end_ns: export.uptime_ns(last),
        bytes: Some(d_octets.into()),
        packets: Some(d_pkts.into()),
        src_addr: Some(srcaddr.into()),
        dst_addr: Some(dstaddr.into()),
        etype: Some(ETHER_TYPE_IPV4),
        proto: Some(prot),
        src_port: ports.map(|(src, _)| src),
        dst_port: ports.map(|(_, dst)| dst),
        icmp_type: icmp.map(|[icmp_type, _]| icmp_type),
        icmp_code: icmp.map(|[_, icmp_code]| icmp_code),
        in_if: Some(input.into()),
        out_if: Some(output.into()),
        ip_tos: Some(tos),
        tcp_flags: Some(tcp_flags.into()),
        src_as: Some(src_as.into()),
        dst_as: Some(dst_as.into()),
        next_hop: Some(nexthop.into()),
        src_net: Some(src_mask),
        dst_net: Some(dst_mask),
        ..CommonFlow::new(
            FlowType::NetflowV5,
            time_received_ns,
            sampler_address,
            header.flow_sequence,
        )
    }
}
