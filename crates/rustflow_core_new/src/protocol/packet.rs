use crate::protocol::{Protocol, ipfix, netflow_v5, netflow_v9, sflow_v5};

/// A parsed packet of any protocol. Serializes as the packet itself,
/// without a wrapper naming the protocol.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
pub enum Packet {
    NetflowV5(netflow_v5::Packet),
    NetflowV9(netflow_v9::Packet),
    Ipfix(ipfix::Packet),
    SflowV5(sflow_v5::Packet),
}

impl Packet {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::NetflowV5(_) => Protocol::NetflowV5,
            Self::NetflowV9(_) => Protocol::NetflowV9,
            Self::Ipfix(_) => Protocol::Ipfix,
            Self::SflowV5(_) => Protocol::SflowV5,
        }
    }

    /// The records the packet carries that become records when converted:
    /// flow records, decoded data and options records, and flow samples.
    pub fn record_count(&self) -> usize {
        match self {
            Self::NetflowV5(packet) => packet.flow_records.len(),
            Self::NetflowV9(packet) => packet
                .flow_sets
                .iter()
                .map(|set| match set {
                    netflow_v9::FlowSet::Data(data) => data.records.len(),
                    netflow_v9::FlowSet::OptionsData(data) => data.records.len(),
                    _ => 0,
                })
                .sum(),
            Self::Ipfix(packet) => packet
                .sets
                .iter()
                .map(|set| match set {
                    ipfix::Set::Data(data) => data.records.len(),
                    ipfix::Set::OptionsData(data) => data.records.len(),
                    _ => 0,
                })
                .sum(),
            Self::SflowV5(packet) => packet
                .samples
                .iter()
                .filter(|sample| {
                    matches!(
                        sample,
                        sflow_v5::Sample::Flow(_) | sflow_v5::Sample::ExpandedFlow(_)
                    )
                })
                .count(),
        }
    }
}
