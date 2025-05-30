// NetFlow v5
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108

pub const NETFLOW_V5_VERSION: u16 = 5;

#[derive(Debug, Clone)]
pub struct NetFlowV5 {
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    pub sysuptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
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
    pub srcaddr: [u8; 4],
    pub dstaddr: [u8; 4],
    pub nexthop: [u8; 4],
    pub input: u16,
    pub output: u16,
    pub dpkts: u32,
    pub dockts: u32,
    pub first: u32,
    pub last: u32,
    pub srcport: u16,
    pub dstport: u16,
    pub pad1: u8,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}
