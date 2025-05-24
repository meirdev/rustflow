use nom::Parser;
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, verify};
use nom::multi::many;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, ToUsize};

// NetFlow v5
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html

#[derive(Debug, Clone)]
pub struct NetFlowV5 {
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone)]
pub struct Header {
    /// NetFlow export format version number.
    pub version: u16,
    /// Number of flows exported in this packet (1-30).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen.
    pub flow_sequence: u32,
    /// Type of flow-switching engine.
    pub engine_type: u8,
    /// Slot number of the flow-switching engine.
    pub engine_id: u8,
    /// First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval.
    pub sampling_interval: u16,
}

impl Header {
    pub fn get_sampling_mode(&self) -> u16 {
        self.sampling_interval >> 14
    }

    pub fn get_sampling_interval(&self) -> u16 {
        self.sampling_interval & 0x3fff
    }
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// Source IP address.
    pub src_addr: [u8; 4],
    /// Destination IP address.
    pub dst_addr: [u8; 4],
    /// IP address of next hop route.
    pub next_hop: [u8; 4],
    /// SNMP index of input interface.
    pub input: u16,
    /// SNMP index of output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_ockts: u32,
    /// SysUptime at start of flow.
    pub first: u32,
    /// SysUptime at the time the last packet of the flow was received.
    pub last: u32,
    /// TCP/UDP source port number or equivalent.
    pub src_port: u16,
    /// TCP/UDP destination port number or equivalent.
    pub dst_port: u16,
    /// Unused (zero) bytes.
    pub pad1: u8,
    /// Cumulative OR of TCP flags.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17).
    pub prot: u8,
    /// IP type of service (ToS).
    pub tos: u8,
    /// Autonomous system number of the source, either origin or peer.
    pub src_as: u16,
    /// Autonomous system number of the destination, either origin or peer.
    pub dst_as: u16,
    /// Source address prefix mask bits.
    pub src_mask: u8,
    /// Destination address prefix mask bits.
    pub dst_mask: u8,
    /// Unused (zero) bytes.
    pub pad2: u16,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == 5).parse(input)?;
    let (input, count) = verify(be_u16, |i| (1..=30).contains(i)).parse(input)?;
    let (input, sys_uptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, unix_nsecs) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = be_u8(input)?;
    let (input, engine_id) = be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            engine_type,
            engine_id,
            sampling_interval,
        },
    ))
}

fn parse_flow_record(input: &[u8]) -> IResult<&[u8], FlowRecord> {
    let (input, src_addr) = take(4u8)(input)?;
    let (input, dst_addr) = take(4u8)(input)?;
    let (input, next_hop) = take(4u8)(input)?;
    let (input, input_) = be_u16(input)?;
    let (input, output) = be_u16(input)?;
    let (input, d_pkts) = be_u32(input)?;
    let (input, d_ockts) = be_u32(input)?;
    let (input, first) = be_u32(input)?;
    let (input, last) = be_u32(input)?;
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, pad1) = be_u8(input)?;
    let (input, tcp_flags) = be_u8(input)?;
    let (input, prot) = be_u8(input)?;
    let (input, tos) = be_u8(input)?;
    let (input, src_as) = be_u16(input)?;
    let (input, dst_as) = be_u16(input)?;
    let (input, src_mask) = be_u8(input)?;
    let (input, dst_mask) = be_u8(input)?;
    let (input, pad2) = be_u16(input)?;

    Ok((
        input,
        FlowRecord {
            src_addr: [src_addr[0], src_addr[1], src_addr[2], src_addr[3]],
            dst_addr: [dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]],
            next_hop: [next_hop[0], next_hop[1], next_hop[2], next_hop[3]],
            input: input_,
            output,
            d_pkts,
            d_ockts,
            first,
            last,
            src_port,
            dst_port,
            pad1,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            pad2,
        },
    ))
}

pub fn parse(input: &[u8]) -> IResult<&[u8], NetFlowV5> {
    let (input, header) = parse_header(input)?;
    let (input, flow_records) =
        all_consuming(many(0..=header.count.to_usize(), parse_flow_record)).parse(input)?;

    Ok((
        input,
        NetFlowV5 {
            header,
            flow_records,
        },
    ))
}
