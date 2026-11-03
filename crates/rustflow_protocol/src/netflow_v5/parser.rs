use rustflow_bytes::Reader;

use super::*;
use crate::ParseError;

/// Parses a NetFlow v5 datagram. Bytes after the last flow record are
/// ignored.
pub fn parse(datagram: &[u8]) -> Result<Packet, ParseError> {
    let mut r = Reader::new(datagram);
    let header = parse_header(&mut r)?;
    let flow_records = r.repeat(usize::from(header.count), parse_flow_record)?;

    Ok(Packet {
        header,
        flow_records,
    })
}

fn parse_header(r: &mut Reader) -> Result<Header, ParseError> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(ParseError::Version(version.into()));
    }
    let count = r.u16()?;
    let sys_uptime = r.u32()?;
    let unix_secs = r.u32()?;
    let unix_nsecs = r.u32()?;
    let flow_sequence = r.u32()?;
    let engine_type = r.u8()?;
    let engine_id = r.u8()?;
    let sampling_interval = Sampling::from(r.u16()?);

    Ok(Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    })
}

fn parse_flow_record(r: &mut Reader) -> Result<FlowRecord, ParseError> {
    let srcaddr = r.ipv4()?;
    let dstaddr = r.ipv4()?;
    let nexthop = r.ipv4()?;
    let input = r.u16()?;
    let output = r.u16()?;
    let d_pkts = r.u32()?;
    let d_octets = r.u32()?;
    let first = r.u32()?;
    let last = r.u32()?;
    let srcport = r.u16()?;
    let dstport = r.u16()?;
    // pad1
    r.skip(1)?;
    let tcp_flags = r.u8()?;
    let prot = r.u8()?;
    let tos = r.u8()?;
    let src_as = r.u16()?;
    let dst_as = r.u16()?;
    let src_mask = r.u8()?;
    let dst_mask = r.u8()?;
    // pad2
    r.skip(2)?;

    Ok(FlowRecord {
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
    })
}
