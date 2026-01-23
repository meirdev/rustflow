use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::Serialize;

use macaddr::MacAddr6;

#[derive(Debug, Clone, Serialize)]
pub enum DataValue {
    Null,
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    MacAddr(MacAddr6),
    U8(u8),
    U16(u16),
    U32(u32),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

#[derive(Debug, Clone, Serialize)]
pub struct SFlowV5 {
    pub version: u32,
    pub agent_address: IpAddr,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Sample {
    Flow(FlowSample),
    Counter(CounterSample),
    ExpandedFlow(ExpandedFlowSample),
    Drop(DropSample),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
pub enum DataFormat {}

#[derive(Debug, Clone, Serialize)]
pub struct SampleHeader {
    pub format: u32,
    pub length: u32,
    pub sample_sequence_number: u32,
    pub source_id_type: u32,
    pub source_id_value: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSample {
    pub header: SampleHeader,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input: u32,
    pub output: u32,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterSample {
    pub header: SampleHeader,
    pub records: Vec<CounterRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpandedFlowSample {
    pub header: SampleHeader,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input_if_format: u32,
    pub input_if_value: u32,
    pub output_if_format: u32,
    pub output_if_value: u32,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DropSample {
    pub header: SampleHeader,
    pub drops: u32,
    pub input: u32,
    pub output: u32,
    pub reason: DropReason,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordHeader {
    pub data_format: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum FlowRecordType {
    SampledHeader(SampledHeader),
    SampledEthernet(SampledEthernet),
    SampledIpv4(SampledIpv4),
    SampledIpv6(SampledIpv6),
    ExtendedSwitch(ExtendedSwitch),
    ExtendedRouter(ExtendedRouter),
    ExtendedGateway(ExtendedGateway),
    ExtendedUser(ExtendedUser),
    ExtendedUrl(ExtendedUrl),
    ExtendedEgressQueue(ExtendedEgressQueue),
    ExtendedAcl(ExtendedAcl),
    ExtendedFunction(ExtendedFunction),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum FlowType {
    SampledHeader = 1,
    SampledEthernet = 2,
    SampledIpv4 = 3,
    SampledIpv6 = 4,
    ExtendedSwitch = 1001,
    ExtendedRouter = 1002,
    ExtendedGateway = 1003,
    ExtendedUser = 1004,
    ExtendedUrl = 1005,
    ExtendedEgressQueue = 1036,
    ExtendedAcl = 1037,
    ExtendedFunction = 1038,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRecord {
    pub header: RecordHeader,
    pub data: FlowRecordType,
}

#[derive(Debug, Clone, Serialize)]
pub enum CounterRecordType {
    IfCounters(IfCounters),
    EthernetCounters(EthernetCounters),
    TokenringCounters(TokenringCounters),
    VgCounters(VgCounters),
    VlanCounters(VlanCounters),
    Processor(Processor),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum CounterType {
    IfCounters = 1,
    EthernetCounters = 2,
    TokenringCounters = 3,
    VgCounters = 4,
    VlanCounters = 5,
    Processor = 1001,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterRecord {
    pub header: RecordHeader,
    pub data: Vec<CounterRecordType>,
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum HeaderProtocol {
    EthernetIso8023 = 1,
    Iso88024TokenBus = 2,
    Iso88025TokenRing = 3,
    Fddi = 4,
    FrameRelay = 5,
    X25 = 6,
    Ppp = 7,
    Smds = 8,
    Aal5 = 9,
    Aal5Ip = 10,
    Ipv4 = 11,
    Ipv6 = 12,
    Mpls = 13,
    Pos = 14,
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum DropReason {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragNeeded = 4,
    SrcRouteFailed = 5,
    DstNetUnknown = 6,
    DstHostUnknown = 7,
    SrcHostIsolated = 8,
    DstNetProhibited = 9,
    DstHostProhibited = 10,
    DstNetTosUnreachable = 11,
    DstHostTosUnreachable = 12,
    CommAdminProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
    Unknown = 256,
    TtlExceeded = 257,
    Acl = 258,
    NoBufferSpace = 259,
    Red = 260,
    TrafficShaping = 261,
    PktTooBig = 262,
    SrcMacIsMulticast = 263,
    VlanTagMismatch = 264,
    IngressVlanFilter = 265,
    IngressSpanningTreeFilter = 266,
    PortListIsEmpty = 267,
    PortLoopbackFilter = 268,
    BlackholeRoute = 269,
    NonIp = 270,
    UcDipOverMcDmac = 271,
    DipIsLoopbackAddress = 272,
    SipIsMc = 273,
    SipIsLoopbackAddress = 274,
    IpHeaderCorrupted = 275,
    Ipv4SipIsLimitedBc = 276,
    Ipv6McDipReservedScope = 277,
    Ipv6McDipInterfaceLocalScope = 278,
    UnresolvedNeigh = 279,
    McReversePathForwarding = 280,
    NonRoutablePacket = 281,
    DecapError = 282,
    OverlaySmacIsMc = 283,
    UnknownL2 = 284,
    UnknownL3 = 285,
    UnknownL3Exception = 286,
    UnknownBuffer = 287,
    UnknownTunnel = 288,
    UnknownL4 = 289,
    SipIsUnspecified = 290,
    MlagPortIsolated = 291,
    BlackholeArpNeigh = 292,
    SrcMacIsDmac = 293,
    DmacIsReserved = 294,
    SipIsClassE = 295,
    McDmacMismatch = 296,
    SipIsDip = 297,
    DipIsLocalNetwork = 298,
    DipIsLinkLocal = 299,
    OverlaySmacIsDmac = 300,
    EgressVlanFilter = 301,
    UcReversePathForwarding = 302,
    SplitHorizon = 303,
}

pub enum FlowData {
    SampledHeader = 1,
    SampledEthernet = 2,
    SampledIpv4 = 3,
    SampledIpv6 = 4,
    ExtendedSwitch = 1001,
    ExtendedRouter = 1002,
    ExtendedGateway = 1003,
    ExtendedUser = 1004,
    ExtendedUrl = 1005,
    ExtendedEgressQueue = 1036,
    ExtendedAcl = 1037,
    ExtendedFunction = 1038,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampledHeader {
    pub protocol: HeaderProtocol,
    pub frame_length: u32,
    pub stripped: u32,
    pub header: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampledEthernet {
    pub length: u32,
    pub src_mac: MacAddr6,
    pub dst_mac: MacAddr6,
    pub r#type: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampledIpv4 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub tos: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampledIpv6 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum PacketInformationType {
    Header(SampledHeader),
    Ethernet(SampledEthernet),
    Ipv4(SampledIpv4),
    Ipv6(SampledIpv6),
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedSwitch {
    pub src_vlan: u32,
    pub src_priority: u32,
    pub dst_vlan: u32,
    pub dst_priority: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedRouter {
    pub nexthop: IpAddr,
    pub src_mask: u32,
    pub dst_mask: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

#[derive(Debug, Clone, Serialize)]
pub enum AsPathType {
    AsSet(HashSet<u32>),
    AsSequence(HashSet<u32>),
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedGateway {
    pub r#as: u32,
    pub src_as: u32,
    pub src_peer_as: u32,
    pub dst_as_path: AsPathType,
    pub communities: Vec<u32>,
    pub localpref: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedUser {
    pub src_user: String,
    pub dst_user: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum UrlDirection {
    Src = 1,
    Dst = 2,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedUrl {
    pub direction: UrlDirection,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedEgressQueue {
    pub queue: u32,
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum Direction {
    Unknown = 0,
    Ingress = 1,
    Egress = 2,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedAcl {
    pub number: u32,
    pub name: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedFunction {
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum ExtendedDataType {
    Switch(ExtendedSwitch),
    Router(ExtendedRouter),
    Gateway(ExtendedGateway),
    User(ExtendedUser),
    Url(ExtendedUrl),
    EgressQueue(ExtendedEgressQueue),
    Acl(ExtendedAcl),
    Function(ExtendedFunction),
}

#[derive(Debug, Clone, Serialize)]
pub struct IfCounters {
    pub if_index: u32,
    pub if_type: u32,
    pub if_speed: u64,
    pub if_direction: u32,
    pub if_status: u32,
    pub if_in_octets: u64,
    pub if_in_ucast_pkts: u32,
    pub if_in_multicast_pkts: u32,
    pub if_in_broadcast_pkts: u32,
    pub if_in_discards: u32,
    pub if_in_errors: u32,
    pub if_in_unknown_protos: u32,
    pub if_out_octets: u64,
    pub if_out_ucast_pkts: u32,
    pub if_out_multicast_pkts: u32,
    pub if_out_broadcast_pkts: u32,
    pub if_out_discards: u32,
    pub if_out_errors: u32,
    pub if_promiscuous_mode: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscardedPacket {
    pub sequence_number: u32,
    pub source_id: u32,
    pub drops: u32,
    pub inputifindex: u32,
    pub outputifindex: u32,
    pub reason: DropReason,
    pub discard_records: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EthernetCounters {
    pub dot3_stats_alignment_errors: u32,
    pub dot3_stats_fcs_errors: u32,
    pub dot3_stats_single_collision_frames: u32,
    pub dot3_stats_multiple_collision_frames: u32,
    pub dot3_stats_sqetest_errors: u32,
    pub dot3_stats_deferred_transmissions: u32,
    pub dot3_stats_late_collisions: u32,
    pub dot3_stats_excessive_collisions: u32,
    pub dot3_stats_internal_mac_transmit_errors: u32,
    pub dot3_stats_carrier_sense_errors: u32,
    pub dot3_stats_frame_too_longs: u32,
    pub dot3_stats_internal_mac_receive_errors: u32,
    pub dot3_stats_symbol_errors: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenringCounters {
    pub dot5_stats_line_errors: u32,
    pub dot5_stats_burst_errors: u32,
    pub dot5_stats_ac_errors: u32,
    pub dot5_stats_abort_trans_errors: u32,
    pub dot5_stats_internal_errors: u32,
    pub dot5_stats_lost_frame_errors: u32,
    pub dot5_stats_receive_congestions: u32,
    pub dot5_stats_frame_copied_errors: u32,
    pub dot5_stats_token_errors: u32,
    pub dot5_stats_soft_errors: u32,
    pub dot5_stats_hard_errors: u32,
    pub dot5_stats_signal_loss: u32,
    pub dot5_stats_transmit_beacons: u32,
    pub dot5_stats_recoveries: u32,
    pub dot5_stats_lobe_wires: u32,
    pub dot5_stats_removes: u32,
    pub dot5_stats_singles: u32,
    pub dot5_stats_freq_errors: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct VgCounters {
    pub dot12_in_high_priority_frames: u32,
    pub dot12_in_high_priority_octets: u64,
    pub dot12_in_norm_priority_frames: u32,
    pub dot12_in_norm_priority_octets: u64,
    pub dot12_in_ipm_errors: u32,
    pub dot12_in_oversize_frame_errors: u32,
    pub dot12_in_data_errors: u32,
    pub dot12_in_null_addressed_frames: u32,
    pub dot12_out_high_priority_frames: u32,
    pub dot12_out_high_priority_octets: u64,
    pub dot12_transition_into_training: u32,
    pub dot12_hc_in_high_priority_octets: u64,
    pub dot12_hc_in_norm_priority_octets: u64,
    pub dot12_hc_out_high_priority_octets: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VlanCounters {
    pub vlan_id: u32,
    pub octets: u64,
    pub ucast_pkts: u32,
    pub multicast_pkts: u32,
    pub broadcast_pkts: u32,
    pub discards: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Processor {
    pub avg_5s_cpu: i32,
    pub avg_1m_cpu: i32,
    pub avg_5m_cpu: i32,
    pub total_memory: u64,
    pub free_memory: u64,
}
