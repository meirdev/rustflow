use bytes::BufMut;
use chrono::{DateTime, Utc};

use super::parser::{FlowRecord, Header, NetFlowV5Packet};
use crate::common::encoder::Encode;

impl Encode for NetFlowV5Packet {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        Header {
            count: self.flow_records.len() as u16,
            ..self.header.clone()
        }
        .encode(buf);

        for record in &self.flow_records {
            record.encode(buf);
        }
    }
}

impl Encode for Header {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.version);
        buf.put_u16(self.count);
        put_millis(&self.sys_uptime, buf);
        buf.put_u32(self.unix_secs);
        buf.put_u32(self.unix_nsecs);
        buf.put_u32(self.flow_sequence);
        buf.put_u8(self.engine_type);
        buf.put_u8(self.engine_id);
        buf.put_u16(self.sampling_mode << 14 | self.sampling_interval & 0x3fff);
    }
}

impl Encode for FlowRecord {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.srcaddr.octets());
        buf.put_slice(&self.dstaddr.octets());
        buf.put_slice(&self.nexthop.octets());
        buf.put_u16(self.input);
        buf.put_u16(self.output);
        buf.put_u32(self.d_pkts);
        buf.put_u32(self.d_ockts);
        put_millis(&self.first, buf);
        put_millis(&self.last, buf);
        buf.put_u16(self.srcport);
        buf.put_u16(self.dstport);
        buf.put_u8(0);
        buf.put_u8(self.tcp_flags);
        buf.put_u8(self.prot);
        buf.put_u8(self.tos);
        buf.put_u16(self.src_as);
        buf.put_u16(self.dst_as);
        buf.put_u8(self.src_mask);
        buf.put_u8(self.dst_mask);
        buf.put_u16(0);
    }
}

/// The 32-bit millisecond counter the parser turns into a timestamp.
fn put_millis<B: BufMut>(dt: &DateTime<Utc>, buf: &mut B) {
    buf.put_u32(dt.timestamp_millis() as u32);
}
