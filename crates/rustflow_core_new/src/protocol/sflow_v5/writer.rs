use std::net::IpAddr;

use super::*;
use crate::bytes::{Wire, Writer};
use crate::protocol::WriteError;
use crate::protocol::error::fit_u32;

/// Writes `packet` as an sFlow v5 datagram at the end of `buf`. The counts
/// and lengths written are those of what is written. On error, nothing is
/// written.
pub fn write(packet: &Packet, buf: &mut Vec<u8>) -> Result<(), WriteError> {
    Writer::new(buf).transaction(|w| write_datagram(w, packet))
}

fn write_datagram(w: &mut Writer, packet: &Packet) -> Result<(), WriteError> {
    let Header {
        version,
        agent_address,
        sub_agent_id,
        sequence_number,
        uptime,
    } = packet.header;
    w.u32(version);
    write_address(w, agent_address);
    w.u32(sub_agent_id);
    w.u32(sequence_number);
    w.u32(uptime);
    write_array(w, &packet.samples, "sample count", write_sample)
}

/// An XDR variable-length array: its length, then its elements.
fn write_array<T>(
    w: &mut Writer,
    items: &[T],
    field: &'static str,
    mut write: impl FnMut(&mut Writer, &T) -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    w.u32(fit_u32(items.len(), field)?);
    items.iter().try_for_each(|item| write(w, item))
}

fn write_u32s(w: &mut Writer, values: &[u32], field: &'static str) -> Result<(), WriteError> {
    write_array(w, values, field, |w, value| {
        w.u32(*value);
        Ok(())
    })
}

/// XDR variable-length opaque data: its length, then its bytes, padded.
fn write_opaque(w: &mut Writer, bytes: &[u8]) -> Result<(), WriteError> {
    w.u32(fit_u32(bytes.len(), "opaque length")?);
    w.bytes(bytes);
    w.zeros(xdr_padding(bytes.len()));
    Ok(())
}

fn write_address(w: &mut Writer, address: Option<IpAddr>) {
    match address {
        None => w.u32(UNKNOWN_ADDRESS),
        Some(IpAddr::V4(address)) => {
            w.u32(IPV4_ADDRESS);
            w.ipv4(address);
        }
        Some(IpAddr::V6(address)) => {
            w.u32(IPV6_ADDRESS);
            w.ipv6(address);
        }
    }
}

/// A MAC address, padded to eight bytes as XDR pads fixed-length opaque
/// data.
fn write_mac(w: &mut Writer, mac: &[u8; 6]) {
    w.bytes(mac);
    w.zeros(xdr_padding(mac.len()));
}

/// A sample's or a record's format, then what `body` writes as its data:
/// its length, filled in after, then the data, padded.
fn write_formatted(
    w: &mut Writer,
    format: DataFormat,
    body: impl FnOnce(&mut Writer) -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    w.u32(u32::try_from(format)?);
    let start = w.len();
    w.u32(0);
    body(w)?;
    let length = w.len() - start - 4;
    w.set_u32(start, fit_u32(length, "opaque length")?);
    w.zeros(xdr_padding(length));
    Ok(())
}

fn write_unknown(w: &mut Writer, format: DataFormat, data: &[u8]) -> Result<(), WriteError> {
    write_formatted(w, format, |w| {
        w.bytes(data);
        Ok(())
    })
}

fn write_wire(w: &mut Writer, format: DataFormat, record: &impl Wire) -> Result<(), WriteError> {
    write_formatted(w, format, |w| {
        record.write(w);
        Ok(())
    })
}

fn write_sample(w: &mut Writer, sample: &Sample) -> Result<(), WriteError> {
    let standard = DataFormat::standard;
    match sample {
        Sample::Flow(sample) => write_formatted(w, standard(FLOW_SAMPLE), |w| {
            write_flow_sample(w, sample, false)
        }),
        Sample::Counters(sample) => write_formatted(w, standard(COUNTERS_SAMPLE), |w| {
            write_counters_sample(w, sample, false)
        }),
        Sample::ExpandedFlow(sample) => write_formatted(w, standard(FLOW_SAMPLE_EXPANDED), |w| {
            write_flow_sample(w, sample, true)
        }),
        Sample::ExpandedCounters(sample) => {
            write_formatted(w, standard(COUNTERS_SAMPLE_EXPANDED), |w| {
                write_counters_sample(w, sample, true)
            })
        }
        Sample::Discarded(sample) => write_formatted(w, standard(DISCARDED_PACKET), |w| {
            write_discarded_packet(w, sample)
        }),
        Sample::Unknown { format, data } => write_unknown(w, *format, data),
    }
}

/// A source ID, compact or `expanded`.
fn write_data_source(
    w: &mut Writer,
    source_id: DataSource,
    expanded: bool,
) -> Result<(), WriteError> {
    let DataSource {
        source_id_type,
        source_id_index,
    } = source_id;
    if expanded {
        w.u32(source_id_type);
        w.u32(source_id_index);
        return Ok(());
    }
    if source_id_type >= 1 << (32 - SOURCE_INDEX_BITS) {
        return Err(too_large("source ID type", source_id_type));
    }
    if source_id_index >= 1 << SOURCE_INDEX_BITS {
        return Err(too_large("source ID index", source_id_index));
    }
    w.u32((source_id_type << SOURCE_INDEX_BITS) | source_id_index);
    Ok(())
}

/// An interface, compact or `expanded`.
fn write_interface(w: &mut Writer, interface: Interface, expanded: bool) -> Result<(), WriteError> {
    let Interface { format, value } = interface;
    if expanded {
        w.u32(format);
        w.u32(value);
        return Ok(());
    }
    if format >= 1 << (32 - INTERFACE_VALUE_BITS) {
        return Err(too_large("interface format", format));
    }
    if value >= 1 << INTERFACE_VALUE_BITS {
        return Err(too_large("interface value", value));
    }
    w.u32((format << INTERFACE_VALUE_BITS) | value);
    Ok(())
}

fn write_flow_sample(
    w: &mut Writer,
    sample: &FlowSample,
    expanded: bool,
) -> Result<(), WriteError> {
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
    w.u32(*sequence_number);
    write_data_source(w, *source_id, expanded)?;
    w.u32(*sampling_rate);
    w.u32(*sample_pool);
    w.u32(*drops);
    write_interface(w, *input, expanded)?;
    write_interface(w, *output, expanded)?;
    write_array(w, records, "flow record count", write_flow_record)
}

fn write_counters_sample(
    w: &mut Writer,
    sample: &CountersSample,
    expanded: bool,
) -> Result<(), WriteError> {
    let CountersSample {
        sequence_number,
        source_id,
        records,
    } = sample;
    w.u32(*sequence_number);
    write_data_source(w, *source_id, expanded)?;
    write_array(w, records, "counter record count", write_counter_record)
}

fn write_discarded_packet(w: &mut Writer, sample: &DiscardedPacket) -> Result<(), WriteError> {
    let DiscardedPacket {
        sequence_number,
        source_id,
        drops,
        input_if_index,
        output_if_index,
        reason,
        records,
    } = sample;
    w.u32(*sequence_number);
    write_data_source(w, *source_id, true)?;
    w.u32(*drops);
    w.u32(*input_if_index);
    w.u32(*output_if_index);
    w.u32((*reason).into());
    write_array(w, records, "flow record count", write_flow_record)
}

fn write_flow_record(w: &mut Writer, record: &FlowRecord) -> Result<(), WriteError> {
    let standard = DataFormat::standard;
    match record {
        FlowRecord::SampledHeader(record) => write_formatted(w, standard(SAMPLED_HEADER), |w| {
            write_sampled_header(w, record)
        }),
        FlowRecord::SampledEthernet(record) => {
            write_formatted(w, standard(SAMPLED_ETHERNET), |w| {
                write_sampled_ethernet(w, record);
                Ok(())
            })
        }
        FlowRecord::SampledIpv4(record) => write_wire(w, standard(SAMPLED_IPV4), record),
        FlowRecord::SampledIpv6(record) => write_wire(w, standard(SAMPLED_IPV6), record),
        FlowRecord::ExtendedSwitch(record) => write_wire(w, standard(EXTENDED_SWITCH), record),
        FlowRecord::ExtendedRouter(record) => write_formatted(w, standard(EXTENDED_ROUTER), |w| {
            write_extended_router(w, record);
            Ok(())
        }),
        FlowRecord::ExtendedGateway(record) => {
            write_formatted(w, standard(EXTENDED_GATEWAY), |w| {
                write_extended_gateway(w, record)
            })
        }
        FlowRecord::ExtendedUser(record) => write_formatted(w, standard(EXTENDED_USER), |w| {
            write_extended_user(w, record)
        }),
        FlowRecord::ExtendedUrl(record) => {
            write_formatted(w, standard(EXTENDED_URL), |w| write_extended_url(w, record))
        }
        FlowRecord::ExtendedEgressQueue(ExtendedEgressQueue { queue }) => {
            write_formatted(w, standard(EXTENDED_EGRESS_QUEUE), |w| {
                w.u32(*queue);
                Ok(())
            })
        }
        FlowRecord::ExtendedAcl(record) => {
            write_formatted(w, standard(EXTENDED_ACL), |w| write_extended_acl(w, record))
        }
        FlowRecord::ExtendedFunction(ExtendedFunction { symbol }) => {
            write_formatted(w, standard(EXTENDED_FUNCTION), |w| {
                write_opaque(w, symbol.as_bytes())
            })
        }
        FlowRecord::Unknown { format, data } => write_unknown(w, *format, data),
    }
}

fn write_counter_record(w: &mut Writer, record: &CounterRecord) -> Result<(), WriteError> {
    let standard = DataFormat::standard;
    match record {
        CounterRecord::IfCounters(record) => write_wire(w, standard(IF_COUNTERS), record),
        CounterRecord::EthernetCounters(record) => {
            write_wire(w, standard(ETHERNET_COUNTERS), record)
        }
        CounterRecord::TokenringCounters(record) => {
            write_wire(w, standard(TOKENRING_COUNTERS), record)
        }
        CounterRecord::VgCounters(record) => write_wire(w, standard(VG_COUNTERS), record),
        CounterRecord::VlanCounters(record) => write_wire(w, standard(VLAN_COUNTERS), record),
        CounterRecord::Processor(record) => write_wire(w, standard(PROCESSOR), record),
        CounterRecord::Unknown { format, data } => write_unknown(w, *format, data),
    }
}

fn write_sampled_header(w: &mut Writer, record: &SampledHeader) -> Result<(), WriteError> {
    let SampledHeader {
        protocol,
        frame_length,
        stripped,
        header,
    } = record;
    w.u32((*protocol).into());
    w.u32(*frame_length);
    w.u32(*stripped);
    write_opaque(w, header)
}

fn write_sampled_ethernet(w: &mut Writer, record: &SampledEthernet) {
    let SampledEthernet {
        length,
        src_mac,
        dst_mac,
        r#type,
    } = record;
    w.u32(*length);
    write_mac(w, src_mac);
    write_mac(w, dst_mac);
    w.u32(*r#type);
}

fn write_extended_router(w: &mut Writer, record: &ExtendedRouter) {
    let ExtendedRouter {
        nexthop,
        src_mask_len,
        dst_mask_len,
    } = *record;
    write_address(w, nexthop);
    w.u32(src_mask_len);
    w.u32(dst_mask_len);
}

fn write_extended_gateway(w: &mut Writer, record: &ExtendedGateway) -> Result<(), WriteError> {
    let ExtendedGateway {
        nexthop,
        r#as,
        src_as,
        src_peer_as,
        dst_as_path,
        communities,
        localpref,
    } = record;
    write_address(w, *nexthop);
    w.u32(*r#as);
    w.u32(*src_as);
    w.u32(*src_peer_as);
    write_array(
        w,
        dst_as_path,
        "AS path length",
        |w, segment| match segment {
            AsPathSegment::AsSet(ases) => {
                w.u32(AS_SET);
                write_u32s(w, ases, "AS set length")
            }
            AsPathSegment::AsSequence(ases) => {
                w.u32(AS_SEQUENCE);
                write_u32s(w, ases, "AS sequence length")
            }
        },
    )?;
    write_u32s(w, communities, "community count")?;
    w.u32(*localpref);
    Ok(())
}

fn write_extended_user(w: &mut Writer, record: &ExtendedUser) -> Result<(), WriteError> {
    let ExtendedUser {
        src_charset,
        src_user,
        dst_charset,
        dst_user,
    } = record;
    w.u32(*src_charset);
    write_opaque(w, src_user)?;
    w.u32(*dst_charset);
    write_opaque(w, dst_user)
}

fn write_extended_url(w: &mut Writer, record: &ExtendedUrl) -> Result<(), WriteError> {
    let ExtendedUrl {
        direction,
        url,
        host,
    } = record;
    w.u32((*direction).into());
    write_opaque(w, url.as_bytes())?;
    write_opaque(w, host.as_bytes())
}

fn write_extended_acl(w: &mut Writer, record: &ExtendedAcl) -> Result<(), WriteError> {
    let ExtendedAcl {
        number,
        name,
        direction,
    } = record;
    w.u32(*number);
    write_opaque(w, name.as_bytes())?;
    w.u32((*direction).into());
    Ok(())
}
