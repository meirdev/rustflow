use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::combinator::{map, map_opt, verify};
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use rustc_hash::FxHashMap;

use crate::types::{DataRecord, FieldValue, Message, Record, Set};

pub const NETFLOW_V5_VERSION: u16 = 5;

fn parse_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |t| DateTime::<Utc>::from_timestamp_millis(t as i64)).parse(input)
}

pub fn parse_message(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V5_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = parse_timestamp(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    let sampling_mode = sampling_interval >> 14;
    let sampling_interval = sampling_interval & 0x3fff;

    let (input, records) = many(count.to_usize(), |i| {
        let (i, data_record) =
            parse_data_record(i, engine_type, engine_id, sampling_mode, sampling_interval)?;
        Ok((i, Record::Data(data_record)))
    })
    .parse(input)?;

    let export_time =
        DateTime::<Utc>::from_timestamp(unix_secs as i64, unix_nsecs).unwrap_or_default();

    Ok((
        input,
        Message {
            version,
            length: 0,
            export_time: export_time,
            sequence_number: flow_sequence,
            observation_domain_id: 0,
            nf_count: count,
            nf_system_uptime: Some(system_uptime),
            sets: vec![Set {
                set_id: 256,
                length: 0,
                records,
            }],
        },
    ))
}

fn parse_data_record(
    input: &[u8],
    engine_type: u8,
    engine_id: u8,
    sampling_mode: u16,
    sampling_interval: u16,
) -> IResult<&[u8], DataRecord> {
    let (input, srcaddr) = parse_ipv4_addr(input)?;
    let (input, dstaddr) = parse_ipv4_addr(input)?;
    let (input, nexthop) = parse_ipv4_addr(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
    let (input, first) = parse_timestamp(input)?;
    let (input, last) = parse_timestamp(input)?;
    let (input, srcport) = be_u16(input)?;
    let (input, dstport) = be_u16(input)?;
    let (input, _) = take(1usize)(input)?;
    let (input, tcp_flags) = be_u8(input)?;
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, src_as) = be_u16(input)?;
    let (input, dst_as) = be_u16(input)?;
    let (input, src_mask) = be_u8(input)?;
    let (input, dst_mask) = be_u8(input)?;
    let (input, _) = take(2usize)(input)?;

    let mut fields = FxHashMap::default();
    fields.insert((0, 38), FieldValue::Unsigned8(engine_type)); // engineType
    fields.insert((0, 39), FieldValue::Unsigned8(engine_id)); // engineId
    fields.insert((0, 8), FieldValue::Ipv4Address(srcaddr)); // sourceIPv4Address
    fields.insert((0, 12), FieldValue::Ipv4Address(dstaddr)); // destinationIPv4Address
    fields.insert((0, 15), FieldValue::Ipv4Address(nexthop)); // ipNextHopIPv4Address
    fields.insert((0, 10), FieldValue::Unsigned16(input_)); // ingressInterface
    fields.insert((0, 14), FieldValue::Unsigned16(output)); // egressInterface
    fields.insert((0, 2), FieldValue::Unsigned32(d_pkts)); // packetDeltaCount
    fields.insert((0, 1), FieldValue::Unsigned32(d_ockts)); // octetDeltaCount
    fields.insert((0, 152), FieldValue::DateTimeMilliseconds(first)); // flowStartMilliseconds
    fields.insert((0, 153), FieldValue::DateTimeMilliseconds(last)); // flowEndMilliseconds
    fields.insert((0, 7), FieldValue::Unsigned16(srcport)); // sourceTransportPort
    fields.insert((0, 11), FieldValue::Unsigned16(dstport)); // destinationTransportPort
    fields.insert((0, 6), FieldValue::Unsigned8(tcp_flags)); // tcpControlBits
    fields.insert((0, 4), FieldValue::Unsigned8(prot)); // protocolIdentifier
    fields.insert((0, 5), FieldValue::Unsigned8(tos)); // ipClassOfService
    fields.insert((0, 16), FieldValue::Unsigned16(src_as)); // bgpSourceAsNumber
    fields.insert((0, 17), FieldValue::Unsigned16(dst_as)); // bgpDestinationAsNumber
    fields.insert((0, 9), FieldValue::Unsigned8(src_mask)); // sourceIPv4PrefixLength
    fields.insert((0, 13), FieldValue::Unsigned8(dst_mask)); // destinationIPv4PrefixLength
    fields.insert((0, 35), FieldValue::Unsigned8(sampling_mode as u8)); // samplingAlgorithm
    fields.insert((0, 34), FieldValue::Unsigned32(sampling_interval as u32)); // samplingInterval

    Ok((input, DataRecord(fields)))
}
