use std::net::IpAddr;
use std::str::from_utf8;

use rustflow_bytes::{Reader, Truncated};

use super::*;
use crate::ParseError;

/// Parses an sFlow v5 datagram. A sample or a record of a format this crate
/// does not know, or one that does not parse, is kept as bytes; so are bytes
/// after a sample's or a record's last field. Bytes after the last sample
/// are ignored.
pub fn parse(datagram: &[u8]) -> Result<Packet, ParseError> {
    let mut r = Reader::new(datagram);
    let header = parse_header(&mut r)?;
    let samples = parse_array(&mut r, parse_sample)?;

    Ok(Packet { header, samples })
}

fn parse_header(r: &mut Reader) -> Result<Header, ParseError> {
    let version = r.u32()?;
    if version != VERSION {
        return Err(ParseError::Version(version));
    }
    let agent_address = parse_address(r)?;
    let sub_agent_id = r.u32()?;
    let sequence_number = r.u32()?;
    let uptime = r.u32()?;

    Ok(Header {
        version,
        agent_address,
        sub_agent_id,
        sequence_number,
        uptime,
    })
}

/// An XDR variable-length array: its length, then its elements.
fn parse_array<T, E: From<Truncated>>(
    r: &mut Reader,
    parse: impl FnMut(&mut Reader) -> Result<T, E>,
) -> Result<Vec<T>, E> {
    let count = parse_length(r)?;
    r.repeat(count, parse)
}

fn parse_u32s(r: &mut Reader) -> Result<Vec<u32>, Truncated> {
    parse_array(r, |r| r.u32())
}

fn parse_length(r: &mut Reader) -> Result<usize, Truncated> {
    Ok(usize::try_from(r.u32()?).unwrap_or(usize::MAX))
}

/// XDR variable-length opaque data: its length, then its bytes, padded.
fn parse_opaque<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Truncated> {
    let length = parse_length(r)?;
    let bytes = r.bytes(length)?;
    r.skip(xdr_padding(length))?;

    Ok(bytes)
}

fn parse_string(r: &mut Reader) -> Result<String, ParseError> {
    let bytes = parse_opaque(r)?;
    from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ParseError::Utf8)
}

fn parse_address(r: &mut Reader) -> Result<Option<IpAddr>, ParseError> {
    match r.u32()? {
        UNKNOWN_ADDRESS => Ok(None),
        IPV4_ADDRESS => Ok(Some(IpAddr::V4(r.ipv4()?))),
        IPV6_ADDRESS => Ok(Some(IpAddr::V6(r.ipv6()?))),
        address_type => Err(ParseError::AddressType(address_type)),
    }
}

/// A MAC address, padded to eight bytes as XDR pads fixed-length opaque
/// data.
fn parse_mac(r: &mut Reader) -> Result<[u8; 6], Truncated> {
    let mac = r.array()?;
    r.skip(xdr_padding(6))?;

    Ok(mac)
}

/// A sample's or a record's format, then its data.
fn parse_formatted<'a>(r: &mut Reader<'a>) -> Result<(DataFormat, &'a [u8]), Truncated> {
    let format = DataFormat::from(r.u32()?);
    let data = parse_opaque(r)?;

    Ok((format, data))
}

fn parse_sample(r: &mut Reader) -> Result<Sample, Truncated> {
    let (format, data) = parse_formatted(r)?;
    let mut d = Reader::new(data);
    let sample = match (format.enterprise, format.format) {
        (0, FLOW_SAMPLE) => parse_flow_sample(&mut d, false).ok().map(Sample::Flow),
        (0, COUNTERS_SAMPLE) => parse_counters_sample(&mut d, false)
            .ok()
            .map(Sample::Counters),
        (0, FLOW_SAMPLE_EXPANDED) => parse_flow_sample(&mut d, true)
            .ok()
            .map(Sample::ExpandedFlow),
        (0, COUNTERS_SAMPLE_EXPANDED) => parse_counters_sample(&mut d, true)
            .ok()
            .map(Sample::ExpandedCounters),
        (0, DISCARDED_PACKET) => parse_discarded_packet(&mut d).ok().map(Sample::Discarded),
        _ => None,
    };

    Ok(sample.unwrap_or_else(|| Sample::Unknown {
        format,
        data: data.to_vec(),
    }))
}

/// A source ID, compact or `expanded`.
fn parse_data_source(r: &mut Reader, expanded: bool) -> Result<DataSource, Truncated> {
    if expanded {
        let source_id_type = r.u32()?;
        let source_id_index = r.u32()?;
        return Ok(DataSource {
            source_id_type,
            source_id_index,
        });
    }
    let source_id = r.u32()?;

    Ok(DataSource {
        source_id_type: source_id >> SOURCE_INDEX_BITS,
        source_id_index: source_id & ((1 << SOURCE_INDEX_BITS) - 1),
    })
}

/// An interface, compact or `expanded`.
fn parse_interface(r: &mut Reader, expanded: bool) -> Result<Interface, Truncated> {
    if expanded {
        let format = r.u32()?;
        let value = r.u32()?;
        return Ok(Interface { format, value });
    }
    let interface = r.u32()?;

    Ok(Interface {
        format: interface >> INTERFACE_VALUE_BITS,
        value: interface & ((1 << INTERFACE_VALUE_BITS) - 1),
    })
}

fn parse_flow_sample(r: &mut Reader, expanded: bool) -> Result<FlowSample, ParseError> {
    let sequence_number = r.u32()?;
    let source_id = parse_data_source(r, expanded)?;
    let sampling_rate = r.u32()?;
    let sample_pool = r.u32()?;
    let drops = r.u32()?;
    let input = parse_interface(r, expanded)?;
    let output = parse_interface(r, expanded)?;
    let records = parse_array(r, parse_flow_record)?;

    Ok(FlowSample {
        sequence_number,
        source_id,
        sampling_rate,
        sample_pool,
        drops,
        input,
        output,
        records,
    })
}

fn parse_counters_sample(r: &mut Reader, expanded: bool) -> Result<CountersSample, ParseError> {
    let sequence_number = r.u32()?;
    let source_id = parse_data_source(r, expanded)?;
    let records = parse_array(r, parse_counter_record)?;

    Ok(CountersSample {
        sequence_number,
        source_id,
        records,
    })
}

fn parse_discarded_packet(r: &mut Reader) -> Result<DiscardedPacket, ParseError> {
    let sequence_number = r.u32()?;
    let source_id = parse_data_source(r, true)?;
    let drops = r.u32()?;
    let input_if_index = r.u32()?;
    let output_if_index = r.u32()?;
    let reason = DropReason::from(r.u32()?);
    let records = parse_array(r, parse_flow_record)?;

    Ok(DiscardedPacket {
        sequence_number,
        source_id,
        drops,
        input_if_index,
        output_if_index,
        reason,
        records,
    })
}

fn parse_flow_record(r: &mut Reader) -> Result<FlowRecord, Truncated> {
    let (format, data) = parse_formatted(r)?;

    let mut d = Reader::new(data);
    let d = &mut d;
    let record = match (format.enterprise, format.format) {
        (0, SAMPLED_HEADER) => parse_sampled_header(d).ok().map(FlowRecord::SampledHeader),
        (0, SAMPLED_ETHERNET) => parse_sampled_ethernet(d)
            .ok()
            .map(FlowRecord::SampledEthernet),
        (0, SAMPLED_IPV4) => parse_sampled_ipv4(d).ok().map(FlowRecord::SampledIpv4),
        (0, SAMPLED_IPV6) => parse_sampled_ipv6(d).ok().map(FlowRecord::SampledIpv6),
        (0, EXTENDED_SWITCH) => parse_extended_switch(d)
            .ok()
            .map(FlowRecord::ExtendedSwitch),
        (0, EXTENDED_ROUTER) => parse_extended_router(d)
            .ok()
            .map(FlowRecord::ExtendedRouter),
        (0, EXTENDED_GATEWAY) => parse_extended_gateway(d)
            .ok()
            .map(FlowRecord::ExtendedGateway),
        (0, EXTENDED_USER) => parse_extended_user(d).ok().map(FlowRecord::ExtendedUser),
        (0, EXTENDED_URL) => parse_extended_url(d).ok().map(FlowRecord::ExtendedUrl),
        (0, EXTENDED_EGRESS_QUEUE) => parse_extended_egress_queue(d)
            .ok()
            .map(FlowRecord::ExtendedEgressQueue),
        (0, EXTENDED_ACL) => parse_extended_acl(d).ok().map(FlowRecord::ExtendedAcl),
        (0, EXTENDED_FUNCTION) => parse_extended_function(d)
            .ok()
            .map(FlowRecord::ExtendedFunction),
        _ => None,
    };

    Ok(record.unwrap_or_else(|| FlowRecord::Unknown {
        format,
        data: data.to_vec(),
    }))
}

fn parse_counter_record(r: &mut Reader) -> Result<CounterRecord, Truncated> {
    let (format, data) = parse_formatted(r)?;

    let mut d = Reader::new(data);
    let d = &mut d;
    let record = match (format.enterprise, format.format) {
        (0, IF_COUNTERS) => parse_if_counters(d).ok().map(CounterRecord::IfCounters),
        (0, ETHERNET_COUNTERS) => parse_ethernet_counters(d)
            .ok()
            .map(CounterRecord::EthernetCounters),
        (0, TOKENRING_COUNTERS) => parse_tokenring_counters(d)
            .ok()
            .map(CounterRecord::TokenringCounters),
        (0, VG_COUNTERS) => parse_vg_counters(d).ok().map(CounterRecord::VgCounters),
        (0, VLAN_COUNTERS) => parse_vlan_counters(d).ok().map(CounterRecord::VlanCounters),
        (0, PROCESSOR) => parse_processor(d).ok().map(CounterRecord::Processor),
        _ => None,
    };

    Ok(record.unwrap_or_else(|| CounterRecord::Unknown {
        format,
        data: data.to_vec(),
    }))
}

fn parse_sampled_header(r: &mut Reader) -> Result<SampledHeader, ParseError> {
    let protocol = HeaderProtocol::from(r.u32()?);
    let frame_length = r.u32()?;
    let stripped = r.u32()?;
    let header = parse_opaque(r)?.to_vec();

    Ok(SampledHeader {
        protocol,
        frame_length,
        stripped,
        header,
    })
}

fn parse_sampled_ethernet(r: &mut Reader) -> Result<SampledEthernet, ParseError> {
    let length = r.u32()?;
    let src_mac = parse_mac(r)?;
    let dst_mac = parse_mac(r)?;
    let r#type = r.u32()?;

    Ok(SampledEthernet {
        length,
        src_mac,
        dst_mac,
        r#type,
    })
}

fn parse_sampled_ipv4(r: &mut Reader) -> Result<SampledIpv4, ParseError> {
    let length = r.u32()?;
    let protocol = r.u32()?;
    let src_ip = r.ipv4()?;
    let dst_ip = r.ipv4()?;
    let src_port = r.u32()?;
    let dst_port = r.u32()?;
    let tcp_flags = r.u32()?;
    let tos = r.u32()?;

    Ok(SampledIpv4 {
        length,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        tos,
    })
}

fn parse_sampled_ipv6(r: &mut Reader) -> Result<SampledIpv6, ParseError> {
    let length = r.u32()?;
    let protocol = r.u32()?;
    let src_ip = r.ipv6()?;
    let dst_ip = r.ipv6()?;
    let src_port = r.u32()?;
    let dst_port = r.u32()?;
    let tcp_flags = r.u32()?;
    let priority = r.u32()?;

    Ok(SampledIpv6 {
        length,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        priority,
    })
}

fn parse_extended_switch(r: &mut Reader) -> Result<ExtendedSwitch, ParseError> {
    let src_vlan = r.u32()?;
    let src_priority = r.u32()?;
    let dst_vlan = r.u32()?;
    let dst_priority = r.u32()?;

    Ok(ExtendedSwitch {
        src_vlan,
        src_priority,
        dst_vlan,
        dst_priority,
    })
}

fn parse_extended_router(r: &mut Reader) -> Result<ExtendedRouter, ParseError> {
    let nexthop = parse_address(r)?;
    let src_mask_len = r.u32()?;
    let dst_mask_len = r.u32()?;

    Ok(ExtendedRouter {
        nexthop,
        src_mask_len,
        dst_mask_len,
    })
}

fn parse_extended_gateway(r: &mut Reader) -> Result<ExtendedGateway, ParseError> {
    let nexthop = parse_address(r)?;
    let r#as = r.u32()?;
    let src_as = r.u32()?;
    let src_peer_as = r.u32()?;
    let dst_as_path = parse_array(r, parse_as_path_segment)?;
    let communities = parse_u32s(r)?;
    let localpref = r.u32()?;

    Ok(ExtendedGateway {
        nexthop,
        r#as,
        src_as,
        src_peer_as,
        dst_as_path,
        communities,
        localpref,
    })
}

fn parse_as_path_segment(r: &mut Reader) -> Result<AsPathSegment, ParseError> {
    match r.u32()? {
        AS_SET => Ok(AsPathSegment::AsSet(parse_u32s(r)?)),
        AS_SEQUENCE => Ok(AsPathSegment::AsSequence(parse_u32s(r)?)),
        segment_type => Err(ParseError::AsPathSegmentType(segment_type)),
    }
}

fn parse_extended_user(r: &mut Reader) -> Result<ExtendedUser, ParseError> {
    let src_charset = r.u32()?;
    let src_user = parse_opaque(r)?.to_vec();
    let dst_charset = r.u32()?;
    let dst_user = parse_opaque(r)?.to_vec();

    Ok(ExtendedUser {
        src_charset,
        src_user,
        dst_charset,
        dst_user,
    })
}

fn parse_extended_url(r: &mut Reader) -> Result<ExtendedUrl, ParseError> {
    let direction = UrlDirection::from(r.u32()?);
    let url = parse_string(r)?;
    let host = parse_string(r)?;

    Ok(ExtendedUrl {
        direction,
        url,
        host,
    })
}

fn parse_extended_egress_queue(r: &mut Reader) -> Result<ExtendedEgressQueue, ParseError> {
    let queue = r.u32()?;

    Ok(ExtendedEgressQueue { queue })
}

fn parse_extended_acl(r: &mut Reader) -> Result<ExtendedAcl, ParseError> {
    let number = r.u32()?;
    let name = parse_string(r)?;
    let direction = AclDirection::from(r.u32()?);

    Ok(ExtendedAcl {
        number,
        name,
        direction,
    })
}

fn parse_extended_function(r: &mut Reader) -> Result<ExtendedFunction, ParseError> {
    let symbol = parse_string(r)?;

    Ok(ExtendedFunction { symbol })
}

fn parse_if_counters(r: &mut Reader) -> Result<IfCounters, Truncated> {
    Ok(IfCounters {
        if_index: r.u32()?,
        if_type: r.u32()?,
        if_speed: r.u64()?,
        if_direction: r.u32()?,
        if_status: r.u32()?,
        if_in_octets: r.u64()?,
        if_in_ucast_pkts: r.u32()?,
        if_in_multicast_pkts: r.u32()?,
        if_in_broadcast_pkts: r.u32()?,
        if_in_discards: r.u32()?,
        if_in_errors: r.u32()?,
        if_in_unknown_protos: r.u32()?,
        if_out_octets: r.u64()?,
        if_out_ucast_pkts: r.u32()?,
        if_out_multicast_pkts: r.u32()?,
        if_out_broadcast_pkts: r.u32()?,
        if_out_discards: r.u32()?,
        if_out_errors: r.u32()?,
        if_promiscuous_mode: r.u32()?,
    })
}

fn parse_ethernet_counters(r: &mut Reader) -> Result<EthernetCounters, Truncated> {
    Ok(EthernetCounters {
        dot3_stats_alignment_errors: r.u32()?,
        dot3_stats_fcs_errors: r.u32()?,
        dot3_stats_single_collision_frames: r.u32()?,
        dot3_stats_multiple_collision_frames: r.u32()?,
        dot3_stats_sqe_test_errors: r.u32()?,
        dot3_stats_deferred_transmissions: r.u32()?,
        dot3_stats_late_collisions: r.u32()?,
        dot3_stats_excessive_collisions: r.u32()?,
        dot3_stats_internal_mac_transmit_errors: r.u32()?,
        dot3_stats_carrier_sense_errors: r.u32()?,
        dot3_stats_frame_too_longs: r.u32()?,
        dot3_stats_internal_mac_receive_errors: r.u32()?,
        dot3_stats_symbol_errors: r.u32()?,
    })
}

fn parse_tokenring_counters(r: &mut Reader) -> Result<TokenringCounters, Truncated> {
    Ok(TokenringCounters {
        dot5_stats_line_errors: r.u32()?,
        dot5_stats_burst_errors: r.u32()?,
        dot5_stats_ac_errors: r.u32()?,
        dot5_stats_abort_trans_errors: r.u32()?,
        dot5_stats_internal_errors: r.u32()?,
        dot5_stats_lost_frame_errors: r.u32()?,
        dot5_stats_receive_congestions: r.u32()?,
        dot5_stats_frame_copied_errors: r.u32()?,
        dot5_stats_token_errors: r.u32()?,
        dot5_stats_soft_errors: r.u32()?,
        dot5_stats_hard_errors: r.u32()?,
        dot5_stats_signal_loss: r.u32()?,
        dot5_stats_transmit_beacons: r.u32()?,
        dot5_stats_recoverys: r.u32()?,
        dot5_stats_lobe_wires: r.u32()?,
        dot5_stats_removes: r.u32()?,
        dot5_stats_singles: r.u32()?,
        dot5_stats_freq_errors: r.u32()?,
    })
}

fn parse_vg_counters(r: &mut Reader) -> Result<VgCounters, Truncated> {
    Ok(VgCounters {
        dot12_in_high_priority_frames: r.u32()?,
        dot12_in_high_priority_octets: r.u64()?,
        dot12_in_norm_priority_frames: r.u32()?,
        dot12_in_norm_priority_octets: r.u64()?,
        dot12_in_ipm_errors: r.u32()?,
        dot12_in_oversize_frame_errors: r.u32()?,
        dot12_in_data_errors: r.u32()?,
        dot12_in_null_addressed_frames: r.u32()?,
        dot12_out_high_priority_frames: r.u32()?,
        dot12_out_high_priority_octets: r.u64()?,
        dot12_transition_into_trainings: r.u32()?,
        dot12_hc_in_high_priority_octets: r.u64()?,
        dot12_hc_in_norm_priority_octets: r.u64()?,
        dot12_hc_out_high_priority_octets: r.u64()?,
    })
}

fn parse_vlan_counters(r: &mut Reader) -> Result<VlanCounters, Truncated> {
    Ok(VlanCounters {
        vlan_id: r.u32()?,
        octets: r.u64()?,
        ucast_pkts: r.u32()?,
        multicast_pkts: r.u32()?,
        broadcast_pkts: r.u32()?,
        discards: r.u32()?,
    })
}

fn parse_processor(r: &mut Reader) -> Result<Processor, Truncated> {
    Ok(Processor {
        cpu_5s: r.i32()?,
        cpu_1m: r.i32()?,
        cpu_5m: r.i32()?,
        total_memory: r.u64()?,
        free_memory: r.u64()?,
    })
}
