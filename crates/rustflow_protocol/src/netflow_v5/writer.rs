use rustflow_bytes::Writer;

use super::*;
use crate::WriteError;
use crate::error::fit_u16;

pub fn write(packet: &Packet, buf: &mut Vec<u8>) -> Result<(), WriteError> {
    let mut w = Writer::new(buf);
    write_header(&mut w, &packet.header, packet.flow_records.len())?;
    for record in &packet.flow_records {
        write_flow_record(&mut w, record);
    }
    Ok(())
}

fn write_header(w: &mut Writer, header: &Header, records: usize) -> Result<(), WriteError> {
    let Header {
        version,
        count: _,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    } = *header;
    let count = fit_u16(records, "count")?;
    let sampling_interval = u16::try_from(sampling_interval)?;

    w.u16(version);
    w.u16(count);
    w.u32(sys_uptime);
    w.u32(unix_secs);
    w.u32(unix_nsecs);
    w.u32(flow_sequence);
    w.u8(engine_type);
    w.u8(engine_id);
    w.u16(sampling_interval);
    Ok(())
}

fn write_flow_record(w: &mut Writer, record: &FlowRecord) {
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
    w.ipv4(srcaddr);
    w.ipv4(dstaddr);
    w.ipv4(nexthop);
    w.u16(input);
    w.u16(output);
    w.u32(d_pkts);
    w.u32(d_octets);
    w.u32(first);
    w.u32(last);
    w.u16(srcport);
    w.u16(dstport);
    // pad1
    w.zeros(1);
    w.u8(tcp_flags);
    w.u8(prot);
    w.u8(tos);
    w.u16(src_as);
    w.u16(dst_as);
    w.u8(src_mask);
    w.u8(dst_mask);
    // pad2
    w.zeros(2);
}
