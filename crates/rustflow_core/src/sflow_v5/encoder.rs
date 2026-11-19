use std::fmt;

use bytes::BufMut;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    BufferTooSmall { needed: usize, remaining: usize },
    DataFormat(DataFormat),
    DataSource(DataSource),
    Interface(Interface),
    TooLong { length: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, remaining } => write!(
                f,
                "the datagram needs {needed} octets, the buffer has room for {remaining}"
            ),
            Self::DataFormat(format) => write!(
                f,
                "data format {}:{} does not fit 20 and 12 bits",
                format.enterprise, format.format
            ),
            Self::DataSource(source) => write!(
                f,
                "source ID {}:{} does not fit a compact sample's 8 and 24 bits",
                source.source_id_type, source.source_id_index
            ),
            Self::Interface(interface) => write!(
                f,
                "interface {}:{} does not fit a compact sample's 2 and 30 bits",
                interface.format, interface.value
            ),
            Self::TooLong { length } => {
                write!(f, "{length} is more than a 32-bit length holds")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

type Result<T = usize> = std::result::Result<T, EncodeError>;

pub fn encode_packet(out: &mut impl BufMut, packet: &Packet) -> Result {
    let mut datagram = Vec::new();
    encode_datagram(&mut datagram, packet)?;
    let needed = datagram.len();
    let remaining = out.remaining_mut();
    if remaining < needed {
        return Err(EncodeError::BufferTooSmall { needed, remaining });
    }
    out.put_slice(&datagram);
    Ok(needed)
}

fn encode_datagram(out: &mut Vec<u8>, packet: &Packet) -> Result<()> {
    let Packet { header, samples } = packet;
    let Header {
        version,
        agent_address,
        sub_agent_id,
        sequence_number,
        uptime,
    } = *header;
    out.put_u32(version);
    put_address(out, agent_address);
    out.put_u32(sub_agent_id);
    out.put_u32(sequence_number);
    out.put_u32(uptime);
    encode_array(out, samples, encode_sample)
}

fn encode_formatted(
    out: &mut Vec<u8>,
    format: DataFormat,
    body: impl FnOnce(&mut Vec<u8>) -> Result<()>,
) -> Result<()> {
    out.put_u32(format_word(format)?);
    let length_at = out.len();
    out.put_u32(0);
    body(out)?;

    let length = out.len() - length_at - 4;
    // The opaques and arrays inside a sample or record are shorter than it,
    // so this is the only length that needs checking.
    let field = u32::try_from(length).map_err(|_| EncodeError::TooLong { length })?;
    out[length_at..length_at + 4].copy_from_slice(&field.to_be_bytes());
    out.put_bytes(0, xdr_padding(length));
    Ok(())
}

fn encode_array<T>(
    out: &mut Vec<u8>,
    items: &[T],
    mut encode: impl FnMut(&mut Vec<u8>, &T) -> Result<()>,
) -> Result<()> {
    out.put_u32(items.len() as u32);
    items.iter().try_for_each(|item| encode(out, item))
}

fn put_array<B: BufMut, T>(out: &mut B, items: &[T], mut put: impl FnMut(&mut B, &T)) {
    out.put_u32(items.len() as u32);
    for item in items {
        put(out, item);
    }
}

fn put_u32s(out: &mut impl BufMut, values: &[u32]) {
    put_array(out, values, |out, value| out.put_u32(*value));
}

fn put_opaque(out: &mut impl BufMut, octets: &[u8]) {
    out.put_u32(octets.len() as u32);
    out.put_slice(octets);
    out.put_bytes(0, xdr_padding(octets.len()));
}

fn put_address(out: &mut impl BufMut, address: Option<IpAddr>) {
    match address {
        None => out.put_u32(UNKNOWN_ADDRESS),
        Some(IpAddr::V4(address)) => {
            out.put_u32(IPV4_ADDRESS);
            out.put_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            out.put_u32(IPV6_ADDRESS);
            out.put_slice(&address.octets());
        }
    }
}

fn standard(format: u32) -> DataFormat {
    DataFormat {
        enterprise: 0,
        format,
    }
}

fn format_word(format: DataFormat) -> Result<u32> {
    if format.enterprise >> (32 - FORMAT_BITS) != 0 || format.format >> FORMAT_BITS != 0 {
        return Err(EncodeError::DataFormat(format));
    }
    Ok(format.enterprise << FORMAT_BITS | format.format)
}

// Samples.

fn sample_format(sample: &Sample) -> DataFormat {
    match sample {
        Sample::Flow(_) => standard(FLOW_SAMPLE),
        Sample::Counters(_) => standard(COUNTERS_SAMPLE),
        Sample::ExpandedFlow(_) => standard(FLOW_SAMPLE_EXPANDED),
        Sample::ExpandedCounters(_) => standard(COUNTERS_SAMPLE_EXPANDED),
        Sample::Discarded(_) => standard(DISCARDED_PACKET),
        Sample::Unknown { format, .. } => *format,
    }
}

fn encode_sample(out: &mut Vec<u8>, sample: &Sample) -> Result<()> {
    encode_formatted(out, sample_format(sample), |out| match sample {
        Sample::Flow(sample) => encode_flow_sample(out, sample, false),
        Sample::Counters(sample) => encode_counters_sample(out, sample, false),
        Sample::ExpandedFlow(sample) => encode_flow_sample(out, sample, true),
        Sample::ExpandedCounters(sample) => encode_counters_sample(out, sample, true),
        Sample::Discarded(sample) => encode_discarded_packet(out, sample),
        Sample::Unknown { data, .. } => {
            out.put_slice(data);
            Ok(())
        }
    })
}

fn encode_data_source(out: &mut Vec<u8>, source: DataSource, expanded: bool) -> Result<()> {
    if expanded {
        out.put_u32(source.source_id_type);
        out.put_u32(source.source_id_index);
        return Ok(());
    }
    if source.source_id_type >> (32 - SOURCE_INDEX_BITS) != 0
        || source.source_id_index >> SOURCE_INDEX_BITS != 0
    {
        return Err(EncodeError::DataSource(source));
    }
    out.put_u32(source.source_id_type << SOURCE_INDEX_BITS | source.source_id_index);
    Ok(())
}

/// An interface: compact, the format in the high 2 bits and the value in the
/// low 30, or `expanded`, a word each.
fn encode_interface(out: &mut Vec<u8>, interface: Interface, expanded: bool) -> Result<()> {
    if expanded {
        out.put_u32(interface.format);
        out.put_u32(interface.value);
        return Ok(());
    }
    if interface.format >> (32 - INTERFACE_VALUE_BITS) != 0
        || interface.value >> INTERFACE_VALUE_BITS != 0
    {
        return Err(EncodeError::Interface(interface));
    }
    out.put_u32(interface.format << INTERFACE_VALUE_BITS | interface.value);
    Ok(())
}

fn encode_flow_sample(out: &mut Vec<u8>, sample: &FlowSample, expanded: bool) -> Result<()> {
    let FlowSample {
        sequence_number,
        source_id,
        sampling_rate,
        sample_pool,
        drops,
        input,
        output,
        records,
    } = sample;
    out.put_u32(*sequence_number);
    encode_data_source(out, *source_id, expanded)?;
    out.put_u32(*sampling_rate);
    out.put_u32(*sample_pool);
    out.put_u32(*drops);
    encode_interface(out, *input, expanded)?;
    encode_interface(out, *output, expanded)?;
    encode_array(out, records, encode_flow_record)
}

fn encode_counters_sample(
    out: &mut Vec<u8>,
    sample: &CountersSample,
    expanded: bool,
) -> Result<()> {
    let CountersSample {
        sequence_number,
        source_id,
        records,
    } = sample;
    out.put_u32(*sequence_number);
    encode_data_source(out, *source_id, expanded)?;
    encode_array(out, records, encode_counter_record)
}

fn encode_discarded_packet(out: &mut Vec<u8>, sample: &DiscardedPacket) -> Result<()> {
    let DiscardedPacket {
        sequence_number,
        source_id,
        drops,
        input_if_index,
        output_if_index,
        reason,
        records,
    } = sample;
    out.put_u32(*sequence_number);
    encode_data_source(out, *source_id, true)?;
    out.put_u32(*drops);
    out.put_u32(*input_if_index);
    out.put_u32(*output_if_index);
    out.put_u32((*reason).into());
    encode_array(out, records, encode_flow_record)
}

// Records.

fn encode_flow_record(out: &mut Vec<u8>, record: &FlowRecord) -> Result<()> {
    encode_formatted(out, flow_record_format(record), |out| {
        put_flow_record_body(out, record);
        Ok(())
    })
}

fn encode_counter_record(out: &mut Vec<u8>, record: &CounterRecord) -> Result<()> {
    encode_formatted(out, counter_record_format(record), |out| {
        put_counter_record_body(out, record);
        Ok(())
    })
}

fn flow_record_format(record: &FlowRecord) -> DataFormat {
    match record {
        FlowRecord::SampledHeader(_) => standard(SAMPLED_HEADER),
        FlowRecord::SampledEthernet(_) => standard(SAMPLED_ETHERNET),
        FlowRecord::SampledIpv4(_) => standard(SAMPLED_IPV4),
        FlowRecord::SampledIpv6(_) => standard(SAMPLED_IPV6),
        FlowRecord::ExtendedSwitch(_) => standard(EXTENDED_SWITCH),
        FlowRecord::ExtendedRouter(_) => standard(EXTENDED_ROUTER),
        FlowRecord::ExtendedGateway(_) => standard(EXTENDED_GATEWAY),
        FlowRecord::ExtendedUser(_) => standard(EXTENDED_USER),
        FlowRecord::ExtendedUrl(_) => standard(EXTENDED_URL),
        FlowRecord::ExtendedEgressQueue(_) => standard(EXTENDED_EGRESS_QUEUE),
        FlowRecord::ExtendedAcl(_) => standard(EXTENDED_ACL),
        FlowRecord::ExtendedFunction(_) => standard(EXTENDED_FUNCTION),
        FlowRecord::Unknown { format, .. } => *format,
    }
}

fn counter_record_format(record: &CounterRecord) -> DataFormat {
    match record {
        CounterRecord::IfCounters(_) => standard(IF_COUNTERS),
        CounterRecord::EthernetCounters(_) => standard(ETHERNET_COUNTERS),
        CounterRecord::TokenringCounters(_) => standard(TOKENRING_COUNTERS),
        CounterRecord::VgCounters(_) => standard(VG_COUNTERS),
        CounterRecord::VlanCounters(_) => standard(VLAN_COUNTERS),
        CounterRecord::Processor(_) => standard(PROCESSOR),
        CounterRecord::Unknown { format, .. } => *format,
    }
}

impl AsPathSegment {
    fn ases(&self) -> &[u32] {
        match self {
            Self::AsSet(ases) | Self::AsSequence(ases) => ases,
        }
    }
}

fn put_flow_record_body(out: &mut impl BufMut, record: &FlowRecord) {
    match record {
        FlowRecord::SampledHeader(record) => {
            let SampledHeader {
                protocol,
                frame_length,
                stripped,
                header,
            } = record;
            out.put_u32((*protocol).into());
            out.put_u32(*frame_length);
            out.put_u32(*stripped);
            put_opaque(out, header);
        }
        FlowRecord::SampledEthernet(record) => {
            let SampledEthernet {
                length,
                src_mac,
                dst_mac,
                r#type,
            } = record;
            out.put_u32(*length);
            // MAC addresses are padded to 8 octets, as XDR pads fixed-length
            // opaque data.
            out.put_slice(&src_mac.octets());
            out.put_bytes(0, xdr_padding(6));
            out.put_slice(&dst_mac.octets());
            out.put_bytes(0, xdr_padding(6));
            out.put_u32(*r#type);
        }
        FlowRecord::SampledIpv4(record) => {
            let SampledIpv4 {
                length,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_flags,
                tos,
            } = record;
            out.put_u32(*length);
            out.put_u32(*protocol);
            out.put_slice(&src_ip.octets());
            out.put_slice(&dst_ip.octets());
            out.put_u32(*src_port);
            out.put_u32(*dst_port);
            out.put_u32(*tcp_flags);
            out.put_u32(*tos);
        }
        FlowRecord::SampledIpv6(record) => {
            let SampledIpv6 {
                length,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_flags,
                priority,
            } = record;
            out.put_u32(*length);
            out.put_u32(*protocol);
            out.put_slice(&src_ip.octets());
            out.put_slice(&dst_ip.octets());
            out.put_u32(*src_port);
            out.put_u32(*dst_port);
            out.put_u32(*tcp_flags);
            out.put_u32(*priority);
        }
        FlowRecord::ExtendedSwitch(record) => {
            let ExtendedSwitch {
                src_vlan,
                src_priority,
                dst_vlan,
                dst_priority,
            } = record;
            out.put_u32(*src_vlan);
            out.put_u32(*src_priority);
            out.put_u32(*dst_vlan);
            out.put_u32(*dst_priority);
        }
        FlowRecord::ExtendedRouter(record) => {
            let ExtendedRouter {
                nexthop,
                src_mask_len,
                dst_mask_len,
            } = record;
            put_address(out, *nexthop);
            out.put_u32(*src_mask_len);
            out.put_u32(*dst_mask_len);
        }
        FlowRecord::ExtendedGateway(record) => {
            let ExtendedGateway {
                nexthop,
                r#as,
                src_as,
                src_peer_as,
                dst_as_path,
                communities,
                localpref,
            } = record;
            put_address(out, *nexthop);
            out.put_u32(*r#as);
            out.put_u32(*src_as);
            out.put_u32(*src_peer_as);
            put_array(out, dst_as_path, |out, segment| {
                out.put_u32(match segment {
                    AsPathSegment::AsSet(_) => AS_SET,
                    AsPathSegment::AsSequence(_) => AS_SEQUENCE,
                });
                put_u32s(out, segment.ases());
            });
            put_u32s(out, communities);
            out.put_u32(*localpref);
        }
        FlowRecord::ExtendedUser(record) => {
            let ExtendedUser {
                src_charset,
                src_user,
                dst_charset,
                dst_user,
            } = record;
            out.put_u32(*src_charset);
            put_opaque(out, src_user);
            out.put_u32(*dst_charset);
            put_opaque(out, dst_user);
        }
        FlowRecord::ExtendedUrl(record) => {
            let ExtendedUrl {
                direction,
                url,
                host,
            } = record;
            out.put_u32((*direction).into());
            put_opaque(out, url.as_bytes());
            put_opaque(out, host.as_bytes());
        }
        FlowRecord::ExtendedEgressQueue(record) => {
            let ExtendedEgressQueue { queue } = record;
            out.put_u32(*queue);
        }
        FlowRecord::ExtendedAcl(record) => {
            let ExtendedAcl {
                number,
                name,
                direction,
            } = record;
            out.put_u32(*number);
            put_opaque(out, name.as_bytes());
            out.put_u32((*direction).into());
        }
        FlowRecord::ExtendedFunction(record) => {
            let ExtendedFunction { symbol } = record;
            put_opaque(out, symbol.as_bytes());
        }
        FlowRecord::Unknown { data, .. } => out.put_slice(data),
    }
}

fn put_counter_record_body(out: &mut impl BufMut, record: &CounterRecord) {
    match record {
        CounterRecord::IfCounters(record) => {
            let IfCounters {
                if_index,
                if_type,
                if_speed,
                if_direction,
                if_status,
                if_in_octets,
                if_in_ucast_pkts,
                if_in_multicast_pkts,
                if_in_broadcast_pkts,
                if_in_discards,
                if_in_errors,
                if_in_unknown_protos,
                if_out_octets,
                if_out_ucast_pkts,
                if_out_multicast_pkts,
                if_out_broadcast_pkts,
                if_out_discards,
                if_out_errors,
                if_promiscuous_mode,
            } = record;
            out.put_u32(*if_index);
            out.put_u32(*if_type);
            out.put_u64(*if_speed);
            out.put_u32(*if_direction);
            out.put_u32(*if_status);
            out.put_u64(*if_in_octets);
            for counter in [
                if_in_ucast_pkts,
                if_in_multicast_pkts,
                if_in_broadcast_pkts,
                if_in_discards,
                if_in_errors,
                if_in_unknown_protos,
            ] {
                out.put_u32(*counter);
            }
            out.put_u64(*if_out_octets);
            for counter in [
                if_out_ucast_pkts,
                if_out_multicast_pkts,
                if_out_broadcast_pkts,
                if_out_discards,
                if_out_errors,
                if_promiscuous_mode,
            ] {
                out.put_u32(*counter);
            }
        }
        CounterRecord::EthernetCounters(record) => {
            let EthernetCounters {
                dot3_stats_alignment_errors,
                dot3_stats_fcs_errors,
                dot3_stats_single_collision_frames,
                dot3_stats_multiple_collision_frames,
                dot3_stats_sqe_test_errors,
                dot3_stats_deferred_transmissions,
                dot3_stats_late_collisions,
                dot3_stats_excessive_collisions,
                dot3_stats_internal_mac_transmit_errors,
                dot3_stats_carrier_sense_errors,
                dot3_stats_frame_too_longs,
                dot3_stats_internal_mac_receive_errors,
                dot3_stats_symbol_errors,
            } = record;
            for counter in [
                dot3_stats_alignment_errors,
                dot3_stats_fcs_errors,
                dot3_stats_single_collision_frames,
                dot3_stats_multiple_collision_frames,
                dot3_stats_sqe_test_errors,
                dot3_stats_deferred_transmissions,
                dot3_stats_late_collisions,
                dot3_stats_excessive_collisions,
                dot3_stats_internal_mac_transmit_errors,
                dot3_stats_carrier_sense_errors,
                dot3_stats_frame_too_longs,
                dot3_stats_internal_mac_receive_errors,
                dot3_stats_symbol_errors,
            ] {
                out.put_u32(*counter);
            }
        }
        CounterRecord::TokenringCounters(record) => {
            let TokenringCounters {
                dot5_stats_line_errors,
                dot5_stats_burst_errors,
                dot5_stats_ac_errors,
                dot5_stats_abort_trans_errors,
                dot5_stats_internal_errors,
                dot5_stats_lost_frame_errors,
                dot5_stats_receive_congestions,
                dot5_stats_frame_copied_errors,
                dot5_stats_token_errors,
                dot5_stats_soft_errors,
                dot5_stats_hard_errors,
                dot5_stats_signal_loss,
                dot5_stats_transmit_beacons,
                dot5_stats_recoverys,
                dot5_stats_lobe_wires,
                dot5_stats_removes,
                dot5_stats_singles,
                dot5_stats_freq_errors,
            } = record;
            for counter in [
                dot5_stats_line_errors,
                dot5_stats_burst_errors,
                dot5_stats_ac_errors,
                dot5_stats_abort_trans_errors,
                dot5_stats_internal_errors,
                dot5_stats_lost_frame_errors,
                dot5_stats_receive_congestions,
                dot5_stats_frame_copied_errors,
                dot5_stats_token_errors,
                dot5_stats_soft_errors,
                dot5_stats_hard_errors,
                dot5_stats_signal_loss,
                dot5_stats_transmit_beacons,
                dot5_stats_recoverys,
                dot5_stats_lobe_wires,
                dot5_stats_removes,
                dot5_stats_singles,
                dot5_stats_freq_errors,
            ] {
                out.put_u32(*counter);
            }
        }
        CounterRecord::VgCounters(record) => {
            let VgCounters {
                dot12_in_high_priority_frames,
                dot12_in_high_priority_octets,
                dot12_in_norm_priority_frames,
                dot12_in_norm_priority_octets,
                dot12_in_ipm_errors,
                dot12_in_oversize_frame_errors,
                dot12_in_data_errors,
                dot12_in_null_addressed_frames,
                dot12_out_high_priority_frames,
                dot12_out_high_priority_octets,
                dot12_transition_into_trainings,
                dot12_hc_in_high_priority_octets,
                dot12_hc_in_norm_priority_octets,
                dot12_hc_out_high_priority_octets,
            } = record;
            out.put_u32(*dot12_in_high_priority_frames);
            out.put_u64(*dot12_in_high_priority_octets);
            out.put_u32(*dot12_in_norm_priority_frames);
            out.put_u64(*dot12_in_norm_priority_octets);
            out.put_u32(*dot12_in_ipm_errors);
            out.put_u32(*dot12_in_oversize_frame_errors);
            out.put_u32(*dot12_in_data_errors);
            out.put_u32(*dot12_in_null_addressed_frames);
            out.put_u32(*dot12_out_high_priority_frames);
            out.put_u64(*dot12_out_high_priority_octets);
            out.put_u32(*dot12_transition_into_trainings);
            out.put_u64(*dot12_hc_in_high_priority_octets);
            out.put_u64(*dot12_hc_in_norm_priority_octets);
            out.put_u64(*dot12_hc_out_high_priority_octets);
        }
        CounterRecord::VlanCounters(record) => {
            let VlanCounters {
                vlan_id,
                octets,
                ucast_pkts,
                multicast_pkts,
                broadcast_pkts,
                discards,
            } = record;
            out.put_u32(*vlan_id);
            out.put_u64(*octets);
            out.put_u32(*ucast_pkts);
            out.put_u32(*multicast_pkts);
            out.put_u32(*broadcast_pkts);
            out.put_u32(*discards);
        }
        CounterRecord::Processor(record) => {
            let Processor {
                cpu_5s,
                cpu_1m,
                cpu_5m,
                total_memory,
                free_memory,
            } = record;
            out.put_i32(*cpu_5s);
            out.put_i32(*cpu_1m);
            out.put_i32(*cpu_5m);
            out.put_u64(*total_memory);
            out.put_u64(*free_memory);
        }
        CounterRecord::Unknown { data, .. } => out.put_slice(data),
    }
}
