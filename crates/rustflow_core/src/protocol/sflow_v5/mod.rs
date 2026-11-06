//! sFlow version 5 (sflow.org): a datagram of samples, each a sequence of
//! records. Every sample and record names its format, an enterprise and a
//! number, and carries its length, so formats this crate does not know are
//! kept as bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use num_enum::{FromPrimitive, IntoPrimitive};
pub use parser::parse;
pub use writer::write;

use crate::protocol::WriteError;

mod parser;
#[cfg(test)]
mod tests;
mod writer;

pub const VERSION: u32 = 5;

const UNKNOWN_ADDRESS: u32 = 0;
const IPV4_ADDRESS: u32 = 1;
const IPV6_ADDRESS: u32 = 2;

const FLOW_SAMPLE: u32 = 1;
const COUNTERS_SAMPLE: u32 = 2;
const FLOW_SAMPLE_EXPANDED: u32 = 3;
const COUNTERS_SAMPLE_EXPANDED: u32 = 4;
const DISCARDED_PACKET: u32 = 5;

const SAMPLED_HEADER: u32 = 1;
const SAMPLED_ETHERNET: u32 = 2;
const SAMPLED_IPV4: u32 = 3;
const SAMPLED_IPV6: u32 = 4;
const EXTENDED_SWITCH: u32 = 1001;
const EXTENDED_ROUTER: u32 = 1002;
const EXTENDED_GATEWAY: u32 = 1003;
const EXTENDED_USER: u32 = 1004;
const EXTENDED_URL: u32 = 1005;
const EXTENDED_EGRESS_QUEUE: u32 = 1036;
const EXTENDED_ACL: u32 = 1037;
const EXTENDED_FUNCTION: u32 = 1038;

const IF_COUNTERS: u32 = 1;
const ETHERNET_COUNTERS: u32 = 2;
const TOKENRING_COUNTERS: u32 = 3;
const VG_COUNTERS: u32 = 4;
const VLAN_COUNTERS: u32 = 5;
const PROCESSOR: u32 = 1001;

const AS_SET: u32 = 1;
const AS_SEQUENCE: u32 = 2;

/// The bits of a data format's number; the enterprise takes the rest.
const FORMAT_BITS: u32 = 12;
/// The bits of a compact source ID's index; the type takes the rest.
const SOURCE_INDEX_BITS: u32 = 24;
/// The bits of a compact interface's value; the format takes the rest.
const INTERFACE_VALUE_BITS: u32 = 30;

/// XDR pads variable-length data with zeros to a multiple of four bytes
/// (RFC 4506 section 4.10).
fn xdr_padding(length: usize) -> usize {
    (4 - length % 4) % 4
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub samples: Vec<Sample>,
}

/// The datagram header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    pub version: u32,
    /// The IP address of the sFlow agent; `None` when it is unknown.
    pub agent_address: Option<IpAddr>,
    /// Tells apart the datagram streams of sub-agents of one agent.
    pub sub_agent_id: u32,
    /// Incremented with each datagram the sub-agent sends.
    pub sequence_number: u32,
    /// Milliseconds since the agent last booted.
    pub uptime: u32,
}

/// A sample's or a record's format: a number its enterprise assigns, the
/// enterprise being 0 for sFlow's standard formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataFormat {
    /// The SMI Private Enterprise Code, 20 bits on the wire.
    pub enterprise: u32,
    /// 12 bits on the wire.
    pub format: u32,
}

impl DataFormat {
    const fn standard(format: u32) -> Self {
        Self {
            enterprise: 0,
            format,
        }
    }
}

impl From<u32> for DataFormat {
    fn from(value: u32) -> Self {
        Self {
            enterprise: value >> FORMAT_BITS,
            format: value & ((1 << FORMAT_BITS) - 1),
        }
    }
}

impl TryFrom<DataFormat> for u32 {
    type Error = WriteError;

    fn try_from(data_format: DataFormat) -> Result<Self, WriteError> {
        let DataFormat { enterprise, format } = data_format;
        if enterprise >= 1 << (32 - FORMAT_BITS) {
            return Err(too_large("enterprise", enterprise));
        }
        if format >= 1 << FORMAT_BITS {
            return Err(too_large("data format", format));
        }
        Ok((enterprise << FORMAT_BITS) | format)
    }
}

fn too_large(field: &'static str, value: u32) -> WriteError {
    WriteError::TooLarge {
        field,
        value: usize::try_from(value).unwrap_or(usize::MAX),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Sample {
    Flow(FlowSample),
    Counters(CountersSample),
    /// A flow sample whose source ID and interfaces take 32 bits each.
    ExpandedFlow(FlowSample),
    /// A counters sample whose source ID takes 32 bits for each part.
    ExpandedCounters(CountersSample),
    /// A packet the agent dropped (sFlow drop notifications).
    Discarded(DiscardedPacket),
    /// A sample of a format this crate does not know, or one that does not
    /// parse, as sent.
    Unknown {
        format: DataFormat,
        data: Vec<u8>,
    },
}

/// What a sample describes: an interface, a VLAN or a physical entity,
/// numbered as its type numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSource {
    /// 0 for an ifIndex, 1 for a VLAN, 2 for a physical entity. 8 bits in
    /// a compact sample.
    pub source_id_type: u32,
    /// 24 bits in a compact sample.
    pub source_id_index: u32,
}

/// A packet's input or output interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Interface {
    /// 0 for an ifIndex, 1 for a packet discarded (the value then being the
    /// reason), 2 for several output interfaces (the value then being their
    /// number, 0 if unknown). 2 bits in a compact sample.
    pub format: u32,
    /// 30 bits in a compact sample, where format 0 with value 0x3fffffff
    /// means no interface.
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowSample {
    /// Incremented with each flow sample the source generates.
    pub sequence_number: u32,
    pub source_id: DataSource,
    /// One packet out of every `sampling_rate` is sampled.
    pub sampling_rate: u32,
    /// Packets that could have been sampled.
    pub sample_pool: u32,
    /// Samples dropped for lack of resources.
    pub drops: u32,
    pub input: Interface,
    pub output: Interface,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CountersSample {
    /// Incremented with each counters sample the source generates.
    pub sequence_number: u32,
    pub source_id: DataSource,
    pub records: Vec<CounterRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiscardedPacket {
    /// Incremented with each discarded packet record the source generates.
    pub sequence_number: u32,
    pub source_id: DataSource,
    /// Discarded packets not reported, for lack of resources.
    pub drops: u32,
    /// Zero if unknown.
    pub input_if_index: u32,
    /// Zero if unknown.
    pub output_if_index: u32,
    pub reason: DropReason,
    pub records: Vec<FlowRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FlowRecord {
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
    /// A record of a format this crate does not know, or one that does not
    /// parse, as sent.
    Unknown {
        format: DataFormat,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CounterRecord {
    IfCounters(IfCounters),
    EthernetCounters(EthernetCounters),
    TokenringCounters(TokenringCounters),
    VgCounters(VgCounters),
    VlanCounters(VlanCounters),
    Processor(Processor),
    /// A record of a format this crate does not know, or one that does not
    /// parse, as sent.
    Unknown {
        format: DataFormat,
        data: Vec<u8>,
    },
}

/// The protocol a sampled header starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum HeaderProtocol {
    EthernetIso88023 = 1,
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
    #[num_enum(catch_all)]
    Unassigned(u32),
}

/// The first bytes of a sampled packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SampledHeader {
    pub protocol: HeaderProtocol,
    /// The packet's original length.
    pub frame_length: u32,
    /// Bytes removed from the packet before sampling, such as a trailing
    /// FCS.
    pub stripped: u32,
    pub header: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SampledEthernet {
    /// The MAC packet's length, lower layer encapsulations excluded and FCS
    /// included.
    pub length: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// The Ethernet packet type.
    pub r#type: u32,
}

crate::bytes::wire! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SampledIpv4 {
        /// The IP packet's length, lower layer headers and trailers excluded.
        pub length: u32,
        /// The IP protocol type.
        pub protocol: u32,
        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        pub src_port: u32,
        pub dst_port: u32,
        pub tcp_flags: u32,
        pub tos: u32,
    }
}

crate::bytes::wire! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SampledIpv6 {
        /// The IP packet's length, lower layer headers and trailers excluded.
        pub length: u32,
        /// The IP next header.
        pub protocol: u32,
        pub src_ip: Ipv6Addr,
        pub dst_ip: Ipv6Addr,
        pub src_port: u32,
        pub dst_port: u32,
        pub tcp_flags: u32,
        pub priority: u32,
    }
}

crate::bytes::wire! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ExtendedSwitch {
        /// The 802.1Q VLAN ID of the incoming frame.
        pub src_vlan: u32,
        /// The 802.1p priority of the incoming frame.
        pub src_priority: u32,
        /// The 802.1Q VLAN ID of the outgoing frame.
        pub dst_vlan: u32,
        /// The 802.1p priority of the outgoing frame.
        pub dst_priority: u32,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedRouter {
    /// The IP address of the next hop router; `None` when it is unknown.
    pub nexthop: Option<IpAddr>,
    /// The source address prefix mask, in bits.
    pub src_mask_len: u32,
    /// The destination address prefix mask, in bits.
    pub dst_mask_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedGateway {
    /// The IP address of the border router; `None` when it is unknown.
    pub nexthop: Option<IpAddr>,
    /// The router's own AS.
    pub r#as: u32,
    pub src_as: u32,
    pub src_peer_as: u32,
    pub dst_as_path: Vec<AsPathSegment>,
    pub communities: Vec<u32>,
    pub localpref: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AsPathSegment {
    AsSet(Vec<u32>),
    AsSequence(Vec<u32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedUser {
    /// The MIBEnum of the source user's character set (RFC 2978): 106 for
    /// UTF-8, 0 if unknown.
    pub src_charset: u32,
    pub src_user: Vec<u8>,
    /// The MIBEnum of the destination user's character set.
    pub dst_charset: u32,
    pub dst_user: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum UrlDirection {
    /// The source is the server.
    Src = 1,
    /// The destination is the server.
    Dst = 2,
    #[num_enum(catch_all)]
    Unassigned(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedUrl {
    pub direction: UrlDirection,
    pub url: String,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedEgressQueue {
    /// The output queue the packet was in.
    pub queue: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum AclDirection {
    Unknown = 0,
    Ingress = 1,
    Egress = 2,
    #[num_enum(catch_all)]
    Unassigned(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedAcl {
    /// The ACL's number.
    pub number: u32,
    pub name: String,
    pub direction: AclDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedFunction {
    /// The function in the network stack that discarded the packet.
    pub symbol: String,
}

/// Why a packet was discarded (sFlow drop notifications).
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    MlagPortIsolation = 291,
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
    #[num_enum(catch_all)]
    Unassigned(u32),
}

crate::bytes::wire! {
    /// Generic interface counters (RFC 2233).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct IfCounters {
        pub if_index: u32,
        pub if_type: u32,
        pub if_speed: u64,
        /// 0 unknown, 1 full-duplex, 2 half-duplex, 3 in, 4 out.
        pub if_direction: u32,
        /// Bit 0 the ifAdminStatus (up), bit 1 the ifOperStatus (up).
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
}

crate::bytes::wire! {
    /// Ethernet interface counters (RFC 2358).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct EthernetCounters {
        pub dot3_stats_alignment_errors: u32,
        pub dot3_stats_fcs_errors: u32,
        pub dot3_stats_single_collision_frames: u32,
        pub dot3_stats_multiple_collision_frames: u32,
        pub dot3_stats_sqe_test_errors: u32,
        pub dot3_stats_deferred_transmissions: u32,
        pub dot3_stats_late_collisions: u32,
        pub dot3_stats_excessive_collisions: u32,
        pub dot3_stats_internal_mac_transmit_errors: u32,
        pub dot3_stats_carrier_sense_errors: u32,
        pub dot3_stats_frame_too_longs: u32,
        pub dot3_stats_internal_mac_receive_errors: u32,
        pub dot3_stats_symbol_errors: u32,
    }
}

crate::bytes::wire! {
    /// Token Ring counters (RFC 1748).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        pub dot5_stats_recoverys: u32,
        pub dot5_stats_lobe_wires: u32,
        pub dot5_stats_removes: u32,
        pub dot5_stats_singles: u32,
        pub dot5_stats_freq_errors: u32,
    }
}

crate::bytes::wire! {
    /// 100 BaseVG interface counters (RFC 2020).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        pub dot12_transition_into_trainings: u32,
        pub dot12_hc_in_high_priority_octets: u64,
        pub dot12_hc_in_norm_priority_octets: u64,
        pub dot12_hc_out_high_priority_octets: u64,
    }
}

crate::bytes::wire! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct VlanCounters {
        pub vlan_id: u32,
        pub octets: u64,
        pub ucast_pkts: u32,
        pub multicast_pkts: u32,
        pub broadcast_pkts: u32,
        pub discards: u32,
    }
}

crate::bytes::wire! {
    /// The agent's processor and memory.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Processor {
        /// The 5-second average CPU use, in hundredths of a percent; -1 if
        /// unknown.
        pub cpu_5s: i32,
        /// The 1-minute average CPU use, in hundredths of a percent; -1 if
        /// unknown.
        pub cpu_1m: i32,
        /// The 5-minute average CPU use, in hundredths of a percent; -1 if
        /// unknown.
        pub cpu_5m: i32,
        /// In bytes.
        pub total_memory: u64,
        /// In bytes.
        pub free_memory: u64,
    }
}
