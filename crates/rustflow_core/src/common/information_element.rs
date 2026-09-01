use std::sync::LazyLock;

use num_enum::{IntoPrimitive, TryFromPrimitive};

/// IANA IPFIX Information Elements (commonly used subset)
///
/// See: https://www.iana.org/assignments/ipfix/ipfix.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum InformationElement {
    OctetDeltaCount = 1,
    PacketDeltaCount = 2,
    ProtocolIdentifier = 4,
    IpClassOfService = 5,
    TcpControlBits = 6,
    SourceTransportPort = 7,
    SourceIpv4Address = 8,
    SourceIpv4PrefixLength = 9,
    IngressInterface = 10,
    DestinationTransportPort = 11,
    DestinationIpv4Address = 12,
    DestinationIpv4PrefixLength = 13,
    EgressInterface = 14,
    IpNextHopIpv4Address = 15,
    BgpSourceAsNumber = 16,
    BgpDestinationAsNumber = 17,
    BgpNextHopIpv4Address = 18,
    FlowEndSysUpTime = 21,
    FlowStartSysUpTime = 22,
    SourceIpv6Address = 27,
    DestinationIpv6Address = 28,
    SourceIpv6PrefixLength = 29,
    DestinationIpv6PrefixLength = 30,
    FlowLabelIpv6 = 31,
    IcmpTypeCodeIpv4 = 32,
    SamplingInterval = 34,
    SamplerRandomInterval = 50,
    MinimumTtl = 52,
    MaximumTtl = 53,
    FragmentIdentification = 54,
    SourceMacAddress = 56,
    PostDestinationMacAddress = 57,
    SrcVlan = 58,
    DstVlan = 59,
    IpNextHopIpv6Address = 62,
    BgpNextHopIpv6Address = 63,
    DestinationMacAddress = 80,
    PostSourceMacAddress = 81,
    ForwardingStatus = 89,
    ObservationDomainId = 149,
    FlowStartSeconds = 150,
    FlowEndSeconds = 151,
    FlowStartMilliseconds = 152,
    FlowEndMilliseconds = 153,
    FlowStartMicroseconds = 154,
    FlowEndMicroseconds = 155,
    FlowStartNanoseconds = 156,
    FlowEndNanoseconds = 157,
    FlowStartDeltaMicroseconds = 158,
    FlowEndDeltaMicroseconds = 159,
    IcmpTypeIpv4 = 176,
    IcmpCodeIpv4 = 177,
    IcmpTypeIpv6 = 178,
    IcmpCodeIpv6 = 179,
    // PSAMP (RFC 5477)
    SelectionSequenceId = 301,
    SelectorId = 302,
    SelectorAlgorithm = 304,
    SamplingPacketInterval = 305,
    SamplingPacketSpace = 306,
    SamplingTimeInterval = 307,
    SamplingTimeSpace = 308,
    SamplingSize = 309,
    SamplingPopulation = 310,
    SamplingProbability = 311,
    DataLinkFrameSize = 312,
    IpHeaderPacketSection = 313,
    IpPayloadPacketSection = 314,
    DataLinkFrameSection = 315,
    MplsLabelStackSection = 316,
    MplsPayloadPacketSection = 317,
    SelectorIdTotalPktsObserved = 318,
    SelectorIdTotalPktsSelected = 319,
    ObservationTimeSeconds = 322,
    ObservationTimeMilliseconds = 323,
    ObservationTimeMicroseconds = 324,
    ObservationTimeNanoseconds = 325,
    DigestHashValue = 326,
    HashIpPayloadOffset = 327,
    HashIpPayloadSize = 328,
    HashOutputRangeMin = 329,
    HashOutputRangeMax = 330,
    HashSelectedRangeMin = 331,
    HashSelectedRangeMax = 332,
    HashDigestOutput = 333,
    HashInitialiserValue = 334,
    SelectorName = 335,
}

/// Largest discriminant in [`InformationElement`].
const MAX_IE_ID: u16 = 335;

/// Identifier-indexed lookup table for [`InformationElement::from_id`].
static IE_BY_ID: LazyLock<Box<[Option<InformationElement>]>> = LazyLock::new(|| {
    (0..=MAX_IE_ID)
        .map(|id| InformationElement::try_from(id).ok())
        .collect()
});

impl InformationElement {
    #[inline]
    pub fn from_id(id: u16) -> Option<Self> {
        IE_BY_ID.get(id as usize).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ie_table_matches_derive() {
        for id in 0..=u16::MAX {
            assert_eq!(
                InformationElement::from_id(id),
                InformationElement::try_from(id).ok(),
                "lookup table disagrees with the derive for id {id}; \
                 if a variant above MAX_IE_ID was added, raise it"
            );
        }
    }
}
