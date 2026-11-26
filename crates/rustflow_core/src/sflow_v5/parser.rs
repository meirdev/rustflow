use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use winnow::binary::{be_i32, be_u32, be_u64, be_u128};
use winnow::combinator::{fail, repeat, seq};
use winnow::error::{StrContext, StrContextValue};
use winnow::token::take;
use winnow::{Parser as _, Result};

use super::*;
use crate::ParseError;
use crate::mac_address::{MacAddress, mac_address};

pub fn parse(mut input: &[u8]) -> Result<Packet, ParseError> {
    parse_packet.parse_next(&mut input).map_err(ParseError)
}

fn parse_packet(input: &mut &[u8]) -> Result<Packet> {
    let header = parse_header(input)?;
    let samples = parse_array(input, parse_sample)?;

    Ok(Packet { header, samples })
}

fn parse_header(input: &mut &[u8]) -> Result<Header> {
    seq!(Header {
        version: be_u32
            .verify(|&version| version == VERSION)
            .context(StrContext::Label("version"))
            .context(StrContext::Expected(StrContextValue::Description("5"))),
        agent_address: parse_address,
        sub_agent_id: be_u32,
        sequence_number: be_u32,
        uptime: be_u32,
    })
    .parse_next(input)
}

// XDR (RFC 4506) building blocks.

/// A variable-length array: its length, then its elements.
fn parse_array<'i, T>(
    input: &mut &'i [u8],
    element: impl FnMut(&mut &'i [u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let count = parse_length(input)?;
    repeat(count, element).parse_next(input)
}

fn parse_u32s(input: &mut &[u8]) -> Result<Vec<u32>> {
    parse_array(input, be_u32)
}

fn parse_length(input: &mut &[u8]) -> Result<usize> {
    be_u32
        .map(|length| usize::try_from(length).unwrap_or(usize::MAX))
        .parse_next(input)
}

/// Variable-length opaque data: its length, then its bytes, padded to a
/// multiple of four.
fn parse_opaque<'i>(input: &mut &'i [u8]) -> Result<&'i [u8]> {
    let length = parse_length(input)?;
    let bytes = take(length).parse_next(input)?;
    take(xdr_padding(length)).parse_next(input)?;

    Ok(bytes)
}

/// Fails on invalid UTF-8, which keeps the enclosing record as bytes.
fn parse_string(input: &mut &[u8]) -> Result<String> {
    parse_opaque
        .try_map(|bytes| std::str::from_utf8(bytes).map(str::to_owned))
        .context(StrContext::Label("UTF-8 string"))
        .parse_next(input)
}

fn parse_address(input: &mut &[u8]) -> Result<Option<IpAddr>> {
    match be_u32.parse_next(input)? {
        UNKNOWN_ADDRESS => Ok(None),
        IPV4_ADDRESS => Ok(Some(IpAddr::V4(parse_ipv4(input)?))),
        IPV6_ADDRESS => Ok(Some(IpAddr::V6(parse_ipv6(input)?))),
        _ => fail
            .context(StrContext::Label("address type"))
            .parse_next(input),
    }
}

fn parse_ipv4(input: &mut &[u8]) -> Result<Ipv4Addr> {
    be_u32.map(Ipv4Addr::from).parse_next(input)
}

fn parse_ipv6(input: &mut &[u8]) -> Result<Ipv6Addr> {
    be_u128.map(Ipv6Addr::from).parse_next(input)
}

/// A MAC address, padded to eight bytes as XDR pads fixed-length opaque
/// data.
fn parse_mac(input: &mut &[u8]) -> Result<MacAddress> {
    let mac = mac_address(input)?;
    take(xdr_padding(6)).parse_next(input)?;

    Ok(mac)
}

/// A sample's or a record's format, then its data.
fn parse_formatted<'i>(input: &mut &'i [u8]) -> Result<(DataFormat, &'i [u8])> {
    let format = be_u32.map(DataFormat::from).parse_next(input)?;
    let data = parse_opaque(input)?;

    Ok((format, data))
}

/// Parses a structure from the start of `data`; `None` if it fails. An
/// enterprise may extend its structures at the end, the standard ones
/// included, so octets after the structure are skipped (sFlow v5,
/// `data_format`).
fn parse_whole<'i, T>(
    data: &'i [u8],
    mut parser: impl FnMut(&mut &'i [u8]) -> Result<T>,
) -> Option<T> {
    parser(&mut &*data).ok()
}

// Samples.

fn parse_sample(input: &mut &[u8]) -> Result<Sample> {
    let (format, data) = parse_formatted(input)?;
    let sample = match (format.enterprise, format.format) {
        (0, FLOW_SAMPLE) => parse_whole(data, |i| parse_flow_sample(i, false)).map(Sample::Flow),
        (0, COUNTERS_SAMPLE) => {
            parse_whole(data, |i| parse_counters_sample(i, false)).map(Sample::Counters)
        }
        (0, FLOW_SAMPLE_EXPANDED) => {
            parse_whole(data, |i| parse_flow_sample(i, true)).map(Sample::ExpandedFlow)
        }
        (0, COUNTERS_SAMPLE_EXPANDED) => {
            parse_whole(data, |i| parse_counters_sample(i, true)).map(Sample::ExpandedCounters)
        }
        (0, DISCARDED_PACKET) => parse_whole(data, parse_discarded_packet).map(Sample::Discarded),
        _ => None,
    };

    Ok(sample.unwrap_or_else(|| Sample::Unknown {
        format,
        data: data.to_vec(),
    }))
}

/// A source ID, compact (8-bit type, 24-bit index) or `expanded`.
fn parse_data_source(input: &mut &[u8], expanded: bool) -> Result<DataSource> {
    if expanded {
        return seq!(DataSource {
            source_id_type: be_u32,
            source_id_index: be_u32,
        })
        .parse_next(input);
    }
    let source_id = be_u32.parse_next(input)?;

    Ok(DataSource {
        source_id_type: source_id >> SOURCE_INDEX_BITS,
        source_id_index: source_id & ((1 << SOURCE_INDEX_BITS) - 1),
    })
}

/// An interface, compact (2-bit format, 30-bit value) or `expanded`.
fn parse_interface(input: &mut &[u8], expanded: bool) -> Result<Interface> {
    if expanded {
        return seq!(Interface {
            format: be_u32,
            value: be_u32,
        })
        .parse_next(input);
    }
    let interface = be_u32.parse_next(input)?;

    Ok(Interface {
        format: interface >> INTERFACE_VALUE_BITS,
        value: interface & ((1 << INTERFACE_VALUE_BITS) - 1),
    })
}

fn parse_flow_sample(input: &mut &[u8], expanded: bool) -> Result<FlowSample> {
    seq!(FlowSample {
        sequence_number: be_u32,
        source_id: |i: &mut &[u8]| parse_data_source(i, expanded),
        sampling_rate: be_u32,
        sample_pool: be_u32,
        drops: be_u32,
        input: |i: &mut &[u8]| parse_interface(i, expanded),
        output: |i: &mut &[u8]| parse_interface(i, expanded),
        records: |i: &mut &[u8]| parse_array(i, parse_flow_record),
    })
    .parse_next(input)
}

fn parse_counters_sample(input: &mut &[u8], expanded: bool) -> Result<CountersSample> {
    seq!(CountersSample {
        sequence_number: be_u32,
        source_id: |i: &mut &[u8]| parse_data_source(i, expanded),
        records: |i: &mut &[u8]| parse_array(i, parse_counter_record),
    })
    .parse_next(input)
}

fn parse_discarded_packet(input: &mut &[u8]) -> Result<DiscardedPacket> {
    seq!(DiscardedPacket {
        sequence_number: be_u32,
        source_id: |i: &mut &[u8]| parse_data_source(i, true),
        drops: be_u32,
        input_if_index: be_u32,
        output_if_index: be_u32,
        reason: be_u32.map(DropReason::from),
        records: |i: &mut &[u8]| parse_array(i, parse_flow_record),
    })
    .parse_next(input)
}

// Flow records.

fn parse_flow_record(input: &mut &[u8]) -> Result<FlowRecord> {
    let (format, data) = parse_formatted(input)?;
    let record = match (format.enterprise, format.format) {
        (0, SAMPLED_HEADER) => {
            parse_whole(data, parse_sampled_header).map(FlowRecord::SampledHeader)
        }
        (0, SAMPLED_ETHERNET) => {
            parse_whole(data, parse_sampled_ethernet).map(FlowRecord::SampledEthernet)
        }
        (0, SAMPLED_IPV4) => parse_whole(data, parse_sampled_ipv4).map(FlowRecord::SampledIpv4),
        (0, SAMPLED_IPV6) => parse_whole(data, parse_sampled_ipv6).map(FlowRecord::SampledIpv6),
        (0, EXTENDED_SWITCH) => {
            parse_whole(data, parse_extended_switch).map(FlowRecord::ExtendedSwitch)
        }
        (0, EXTENDED_ROUTER) => {
            parse_whole(data, parse_extended_router).map(FlowRecord::ExtendedRouter)
        }
        (0, EXTENDED_GATEWAY) => {
            parse_whole(data, parse_extended_gateway).map(FlowRecord::ExtendedGateway)
        }
        (0, EXTENDED_USER) => parse_whole(data, parse_extended_user).map(FlowRecord::ExtendedUser),
        (0, EXTENDED_URL) => parse_whole(data, parse_extended_url).map(FlowRecord::ExtendedUrl),
        (0, EXTENDED_EGRESS_QUEUE) => {
            parse_whole(data, parse_extended_egress_queue).map(FlowRecord::ExtendedEgressQueue)
        }
        (0, EXTENDED_ACL) => parse_whole(data, parse_extended_acl).map(FlowRecord::ExtendedAcl),
        (0, EXTENDED_FUNCTION) => {
            parse_whole(data, parse_extended_function).map(FlowRecord::ExtendedFunction)
        }
        _ => None,
    };

    Ok(record.unwrap_or_else(|| FlowRecord::Unknown {
        format,
        data: data.to_vec(),
    }))
}

fn parse_sampled_header(input: &mut &[u8]) -> Result<SampledHeader> {
    seq!(SampledHeader {
        protocol: be_u32.map(HeaderProtocol::from),
        frame_length: be_u32,
        stripped: be_u32,
        header: parse_opaque.map(<[u8]>::to_vec),
    })
    .parse_next(input)
}

fn parse_sampled_ethernet(input: &mut &[u8]) -> Result<SampledEthernet> {
    seq!(SampledEthernet {
        length: be_u32,
        src_mac: parse_mac,
        dst_mac: parse_mac,
        r#type: be_u32,
    })
    .parse_next(input)
}

fn parse_sampled_ipv4(input: &mut &[u8]) -> Result<SampledIpv4> {
    seq!(SampledIpv4 {
        length: be_u32,
        protocol: be_u32,
        src_ip: parse_ipv4,
        dst_ip: parse_ipv4,
        src_port: be_u32,
        dst_port: be_u32,
        tcp_flags: be_u32,
        tos: be_u32,
    })
    .parse_next(input)
}

fn parse_sampled_ipv6(input: &mut &[u8]) -> Result<SampledIpv6> {
    seq!(SampledIpv6 {
        length: be_u32,
        protocol: be_u32,
        src_ip: parse_ipv6,
        dst_ip: parse_ipv6,
        src_port: be_u32,
        dst_port: be_u32,
        tcp_flags: be_u32,
        priority: be_u32,
    })
    .parse_next(input)
}

fn parse_extended_switch(input: &mut &[u8]) -> Result<ExtendedSwitch> {
    seq!(ExtendedSwitch {
        src_vlan: be_u32,
        src_priority: be_u32,
        dst_vlan: be_u32,
        dst_priority: be_u32,
    })
    .parse_next(input)
}

fn parse_extended_router(input: &mut &[u8]) -> Result<ExtendedRouter> {
    seq!(ExtendedRouter {
        nexthop: parse_address,
        src_mask_len: be_u32,
        dst_mask_len: be_u32,
    })
    .parse_next(input)
}

fn parse_extended_gateway(input: &mut &[u8]) -> Result<ExtendedGateway> {
    seq!(ExtendedGateway {
        nexthop: parse_address,
        r#as: be_u32,
        src_as: be_u32,
        src_peer_as: be_u32,
        dst_as_path: |i: &mut &[u8]| parse_array(i, parse_as_path_segment),
        communities: parse_u32s,
        localpref: be_u32,
    })
    .parse_next(input)
}

fn parse_as_path_segment(input: &mut &[u8]) -> Result<AsPathSegment> {
    match be_u32.parse_next(input)? {
        AS_SET => Ok(AsPathSegment::AsSet(parse_u32s(input)?)),
        AS_SEQUENCE => Ok(AsPathSegment::AsSequence(parse_u32s(input)?)),
        _ => fail
            .context(StrContext::Label("AS path segment type"))
            .parse_next(input),
    }
}

fn parse_extended_user(input: &mut &[u8]) -> Result<ExtendedUser> {
    seq!(ExtendedUser {
        src_charset: be_u32,
        src_user: parse_opaque.map(<[u8]>::to_vec),
        dst_charset: be_u32,
        dst_user: parse_opaque.map(<[u8]>::to_vec),
    })
    .parse_next(input)
}

fn parse_extended_url(input: &mut &[u8]) -> Result<ExtendedUrl> {
    seq!(ExtendedUrl {
        direction: be_u32.map(UrlDirection::from),
        url: parse_string,
        host: parse_string,
    })
    .parse_next(input)
}

fn parse_extended_egress_queue(input: &mut &[u8]) -> Result<ExtendedEgressQueue> {
    seq!(ExtendedEgressQueue { queue: be_u32 }).parse_next(input)
}

fn parse_extended_acl(input: &mut &[u8]) -> Result<ExtendedAcl> {
    seq!(ExtendedAcl {
        number: be_u32,
        name: parse_string,
        direction: be_u32.map(AclDirection::from),
    })
    .parse_next(input)
}

fn parse_extended_function(input: &mut &[u8]) -> Result<ExtendedFunction> {
    seq!(ExtendedFunction {
        symbol: parse_string,
    })
    .parse_next(input)
}

// Counter records.

fn parse_counter_record(input: &mut &[u8]) -> Result<CounterRecord> {
    let (format, data) = parse_formatted(input)?;
    let record = match (format.enterprise, format.format) {
        (0, IF_COUNTERS) => parse_whole(data, parse_if_counters).map(CounterRecord::IfCounters),
        (0, ETHERNET_COUNTERS) => {
            parse_whole(data, parse_ethernet_counters).map(CounterRecord::EthernetCounters)
        }
        (0, TOKENRING_COUNTERS) => {
            parse_whole(data, parse_tokenring_counters).map(CounterRecord::TokenringCounters)
        }
        (0, VG_COUNTERS) => parse_whole(data, parse_vg_counters).map(CounterRecord::VgCounters),
        (0, VLAN_COUNTERS) => {
            parse_whole(data, parse_vlan_counters).map(CounterRecord::VlanCounters)
        }
        (0, PROCESSOR) => parse_whole(data, parse_processor).map(CounterRecord::Processor),
        _ => None,
    };

    Ok(record.unwrap_or_else(|| CounterRecord::Unknown {
        format,
        data: data.to_vec(),
    }))
}

fn parse_if_counters(input: &mut &[u8]) -> Result<IfCounters> {
    seq!(IfCounters {
        if_index: be_u32,
        if_type: be_u32,
        if_speed: be_u64,
        if_direction: be_u32,
        if_status: be_u32,
        if_in_octets: be_u64,
        if_in_ucast_pkts: be_u32,
        if_in_multicast_pkts: be_u32,
        if_in_broadcast_pkts: be_u32,
        if_in_discards: be_u32,
        if_in_errors: be_u32,
        if_in_unknown_protos: be_u32,
        if_out_octets: be_u64,
        if_out_ucast_pkts: be_u32,
        if_out_multicast_pkts: be_u32,
        if_out_broadcast_pkts: be_u32,
        if_out_discards: be_u32,
        if_out_errors: be_u32,
        if_promiscuous_mode: be_u32,
    })
    .parse_next(input)
}

fn parse_ethernet_counters(input: &mut &[u8]) -> Result<EthernetCounters> {
    seq!(EthernetCounters {
        dot3_stats_alignment_errors: be_u32,
        dot3_stats_fcs_errors: be_u32,
        dot3_stats_single_collision_frames: be_u32,
        dot3_stats_multiple_collision_frames: be_u32,
        dot3_stats_sqe_test_errors: be_u32,
        dot3_stats_deferred_transmissions: be_u32,
        dot3_stats_late_collisions: be_u32,
        dot3_stats_excessive_collisions: be_u32,
        dot3_stats_internal_mac_transmit_errors: be_u32,
        dot3_stats_carrier_sense_errors: be_u32,
        dot3_stats_frame_too_longs: be_u32,
        dot3_stats_internal_mac_receive_errors: be_u32,
        dot3_stats_symbol_errors: be_u32,
    })
    .parse_next(input)
}

fn parse_tokenring_counters(input: &mut &[u8]) -> Result<TokenringCounters> {
    seq!(TokenringCounters {
        dot5_stats_line_errors: be_u32,
        dot5_stats_burst_errors: be_u32,
        dot5_stats_ac_errors: be_u32,
        dot5_stats_abort_trans_errors: be_u32,
        dot5_stats_internal_errors: be_u32,
        dot5_stats_lost_frame_errors: be_u32,
        dot5_stats_receive_congestions: be_u32,
        dot5_stats_frame_copied_errors: be_u32,
        dot5_stats_token_errors: be_u32,
        dot5_stats_soft_errors: be_u32,
        dot5_stats_hard_errors: be_u32,
        dot5_stats_signal_loss: be_u32,
        dot5_stats_transmit_beacons: be_u32,
        dot5_stats_recoverys: be_u32,
        dot5_stats_lobe_wires: be_u32,
        dot5_stats_removes: be_u32,
        dot5_stats_singles: be_u32,
        dot5_stats_freq_errors: be_u32,
    })
    .parse_next(input)
}

fn parse_vg_counters(input: &mut &[u8]) -> Result<VgCounters> {
    seq!(VgCounters {
        dot12_in_high_priority_frames: be_u32,
        dot12_in_high_priority_octets: be_u64,
        dot12_in_norm_priority_frames: be_u32,
        dot12_in_norm_priority_octets: be_u64,
        dot12_in_ipm_errors: be_u32,
        dot12_in_oversize_frame_errors: be_u32,
        dot12_in_data_errors: be_u32,
        dot12_in_null_addressed_frames: be_u32,
        dot12_out_high_priority_frames: be_u32,
        dot12_out_high_priority_octets: be_u64,
        dot12_transition_into_trainings: be_u32,
        dot12_hc_in_high_priority_octets: be_u64,
        dot12_hc_in_norm_priority_octets: be_u64,
        dot12_hc_out_high_priority_octets: be_u64,
    })
    .parse_next(input)
}

fn parse_vlan_counters(input: &mut &[u8]) -> Result<VlanCounters> {
    seq!(VlanCounters {
        vlan_id: be_u32,
        octets: be_u64,
        ucast_pkts: be_u32,
        multicast_pkts: be_u32,
        broadcast_pkts: be_u32,
        discards: be_u32,
    })
    .parse_next(input)
}

fn parse_processor(input: &mut &[u8]) -> Result<Processor> {
    seq!(Processor {
        cpu_5s: be_i32,
        cpu_1m: be_i32,
        cpu_5m: be_i32,
        total_memory: be_u64,
        free_memory: be_u64,
    })
    .parse_next(input)
}
