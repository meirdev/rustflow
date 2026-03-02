use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock};

use chrono::{DateTime, Utc};
use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::parser::{DataRecord, FieldValue};

// Static empty name - encoder doesn't use field names, only FieldValue
static EMPTY_NAME: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(""));

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ipv4: Ipv4Addr,
    pub destination_ipv4: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
}

impl FlowData {
    pub fn to_data_record(&self) -> DataRecord {
        use InformationElement::*;
        let name = EMPTY_NAME.clone();

        DataRecord(vec![
            (
                None,
                SourceIpv4Address.into(),
                name.clone(),
                FieldValue::Ipv4Address(self.source_ipv4),
            ),
            (
                None,
                DestinationIpv4Address.into(),
                name.clone(),
                FieldValue::Ipv4Address(self.destination_ipv4),
            ),
            (
                None,
                ProtocolIdentifier.into(),
                name.clone(),
                FieldValue::Unsigned8(self.protocol),
            ),
            (
                None,
                SourceTransportPort.into(),
                name.clone(),
                FieldValue::Unsigned16(self.source_port),
            ),
            (
                None,
                DestinationTransportPort.into(),
                name.clone(),
                FieldValue::Unsigned16(self.destination_port),
            ),
            (
                None,
                OctetDeltaCount.into(),
                name.clone(),
                FieldValue::Unsigned64(self.octet_count),
            ),
            (
                None,
                PacketDeltaCount.into(),
                name.clone(),
                FieldValue::Unsigned64(self.packet_count),
            ),
            (
                None,
                TcpControlBits.into(),
                name.clone(),
                FieldValue::Unsigned16(self.tcp_flags),
            ),
            (
                None,
                FlowStartMilliseconds.into(),
                name.clone(),
                FieldValue::DateTimeMilliseconds(self.flow_start),
            ),
            (
                None,
                FlowEndMilliseconds.into(),
                name,
                FieldValue::DateTimeMilliseconds(self.flow_end),
            ),
        ])
    }
}

#[derive(Debug)]
pub struct OptionsData {
    pub observation_domain_id: u32,
    pub sampling_packet_interval: u32,
}

impl OptionsData {
    pub fn new(observation_domain_id: u32, sampling_packet_interval: u32) -> Self {
        Self {
            observation_domain_id,
            sampling_packet_interval,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        use InformationElement::*;
        let name = EMPTY_NAME.clone();

        DataRecord(vec![
            (
                None,
                ObservationDomainId.into(),
                name.clone(),
                FieldValue::Unsigned32(self.observation_domain_id),
            ),
            (
                None,
                SamplingPacketInterval.into(),
                name,
                FieldValue::Unsigned32(self.sampling_packet_interval),
            ),
        ])
    }
}
