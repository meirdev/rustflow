use std::fmt;

use bytes::BufMut;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    BufferTooSmall { needed: usize, remaining: usize },
    Sampling(Sampling),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, remaining } => write!(
                f,
                "the packet needs {needed} octets, the buffer has room for {remaining}"
            ),
            Self::Sampling(Sampling { mode, interval }) => write!(
                f,
                "sampling mode {mode} and interval {interval} do not fit in 2 and 14 bits"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

pub fn encode_packet(out: &mut impl BufMut, packet: &Packet) -> Result<usize, EncodeError> {
    let needed = HEADER_LENGTH + packet.flow_records.len() * RECORD_LENGTH;
    let remaining = out.remaining_mut();
    if remaining < needed {
        return Err(EncodeError::BufferTooSmall { needed, remaining });
    }
    let sampling = sampling_word(packet.header.sampling_interval)?;

    let Packet {
        header,
        flow_records,
    } = packet;
    put_header(out, header, sampling);
    for record in flow_records {
        put_flow_record(out, record);
    }
    Ok(needed)
}

fn sampling_word(sampling: Sampling) -> Result<u16, EncodeError> {
    let Sampling { mode, interval } = sampling;
    if mode > 0x03 || interval > SAMPLING_INTERVAL_MASK {
        return Err(EncodeError::Sampling(sampling));
    }
    Ok((u16::from(mode) << 14) | interval)
}

fn put_header(out: &mut impl BufMut, header: &Header, sampling: u16) {
    let Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval: _,
    } = *header;
    out.put_u16(version);
    out.put_u16(count);
    out.put_u32(sys_uptime);
    out.put_u32(unix_secs);
    out.put_u32(unix_nsecs);
    out.put_u32(flow_sequence);
    out.put_u8(engine_type);
    out.put_u8(engine_id);
    out.put_u16(sampling);
}

fn put_flow_record(out: &mut impl BufMut, record: &FlowRecord) {
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
    out.put_slice(&srcaddr.octets());
    out.put_slice(&dstaddr.octets());
    out.put_slice(&nexthop.octets());
    out.put_u16(input);
    out.put_u16(output);
    out.put_u32(d_pkts);
    out.put_u32(d_octets);
    out.put_u32(first);
    out.put_u32(last);
    out.put_u16(srcport);
    out.put_u16(dstport);
    out.put_u8(0); // pad1
    out.put_u8(tcp_flags);
    out.put_u8(prot);
    out.put_u8(tos);
    out.put_u16(src_as);
    out.put_u16(dst_as);
    out.put_u8(src_mask);
    out.put_u8(dst_mask);
    out.put_bytes(0, 2); // pad2
}
