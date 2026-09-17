use std::net::IpAddr;
use std::time::Duration;

use prometheus_client::metrics::gauge::Gauge;
use rustflow::{
    CommonFlow, IERegistry, NetflowPacket, NetflowProcessor, SflowPacket, SflowProcessor,
};
use rustflow_core::ipfix::parser::{IPFIX_VERSION, Record as IpfixRecord};
use rustflow_core::netflow_v5::parser::NETFLOW_V5_VERSION;
use rustflow_core::netflow_v9::parser::{NETFLOW_V9_VERSION, Record as V9Record};
use rustflow_core::sflow_v5::parser::{SFLOW_V5_VERSION, Sample};

use crate::metrics::{self, Metrics};
use crate::sink::pipeline::Pipeline;

pub trait Protocol {
    type Packet;

    /// Display name for startup messages, e.g. "NetFlow".
    const NAME: &'static str;

    /// The metrics family label.
    const FAMILY: &'static str;

    /// Parse a datagram and update protocol state, including template caches.
    fn parse(&mut self, src: IpAddr, payload: &[u8]) -> Option<Self::Packet>;

    /// The packet's data records as normalized flows.
    fn convert(
        &self,
        src: IpAddr,
        packet: &Self::Packet,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow>;

    /// Write the packet in its original structure.
    fn push_raw(packet: &Self::Packet, output: &mut Pipeline);

    /// The metrics label of the packet's version.
    fn version_label(packet: &Self::Packet) -> &'static str;

    /// Read the version label from the datagram header.
    /// Returns `None` for unsupported versions or incomplete version fields.
    fn version_label_of(payload: &[u8]) -> Option<&'static str>;

    /// Number of data records (NetFlow/IPFIX) or flow samples (sFlow).
    fn flow_count(packet: &Self::Packet) -> usize;

    /// Refresh protocol-specific gauges after a successful parse.
    fn update_gauges(&self) {}
}

pub struct Netflow {
    processor: NetflowProcessor,
    v9_exporters: Gauge,
    ipfix_exporters: Gauge,
}

impl Netflow {
    pub fn new(ie_registry: IERegistry, template_timeout: Duration, metrics: &Metrics) -> Self {
        Self {
            processor: NetflowProcessor::new()
                .with_ie_registry(ie_registry)
                .with_template_timeout(template_timeout),
            v9_exporters: metrics.active_exporters(metrics::LABEL_NETFLOW_V9),
            ipfix_exporters: metrics.active_exporters(metrics::LABEL_IPFIX),
        }
    }
}

impl Protocol for Netflow {
    type Packet = NetflowPacket;

    const NAME: &'static str = "NetFlow";
    const FAMILY: &'static str = metrics::LABEL_NETFLOW;

    fn parse(&mut self, src: IpAddr, payload: &[u8]) -> Option<NetflowPacket> {
        self.processor.parse_raw(src, payload)
    }

    fn convert(
        &self,
        src: IpAddr,
        packet: &NetflowPacket,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        self.processor
            .convert_to_flows(src, packet, time_received_ns)
    }

    fn push_raw(packet: &NetflowPacket, output: &mut Pipeline) {
        match packet {
            NetflowPacket::V5(p) => output.push_raw(p),
            NetflowPacket::V9(p) => output.push_raw(p),
            NetflowPacket::Ipfix(p) => output.push_raw(p),
        }
    }

    fn version_label(packet: &NetflowPacket) -> &'static str {
        match packet {
            NetflowPacket::V5(_) => metrics::LABEL_NETFLOW_V5,
            NetflowPacket::V9(_) => metrics::LABEL_NETFLOW_V9,
            NetflowPacket::Ipfix(_) => metrics::LABEL_IPFIX,
        }
    }

    fn version_label_of(payload: &[u8]) -> Option<&'static str> {
        match u16::from_be_bytes(payload.get(..2)?.try_into().ok()?) {
            NETFLOW_V5_VERSION => Some(metrics::LABEL_NETFLOW_V5),
            NETFLOW_V9_VERSION => Some(metrics::LABEL_NETFLOW_V9),
            IPFIX_VERSION => Some(metrics::LABEL_IPFIX),
            _ => None,
        }
    }

    fn flow_count(packet: &NetflowPacket) -> usize {
        match packet {
            NetflowPacket::V5(p) => p.flow_records.len(),
            NetflowPacket::V9(p) => p
                .flow_sets
                .iter()
                .flat_map(|fs| &fs.records)
                .filter(|r| matches!(r, V9Record::Data(_)))
                .count(),
            NetflowPacket::Ipfix(p) => p
                .sets
                .iter()
                .flat_map(|s| &s.records)
                .filter(|r| matches!(r, IpfixRecord::Data(_)))
                .count(),
        }
    }

    fn update_gauges(&self) {
        self.v9_exporters
            .set(self.processor.v9_parsers.len() as i64);
        self.ipfix_exporters
            .set(self.processor.ipfix_parsers.len() as i64);
    }
}

pub struct Sflow {
    processor: SflowProcessor,
}

impl Sflow {
    pub fn new() -> Self {
        Self {
            processor: SflowProcessor::new(),
        }
    }
}

impl Protocol for Sflow {
    type Packet = SflowPacket;

    const NAME: &'static str = "sFlow";
    const FAMILY: &'static str = metrics::LABEL_SFLOW;

    fn parse(&mut self, _src: IpAddr, payload: &[u8]) -> Option<SflowPacket> {
        self.processor.parse_raw(payload)
    }

    fn convert(
        &self,
        _src: IpAddr,
        packet: &SflowPacket,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        SflowProcessor::convert_to_flows(packet, time_received_ns)
    }

    fn push_raw(packet: &SflowPacket, output: &mut Pipeline) {
        match packet {
            SflowPacket::V5(p) => output.push_raw(p),
        }
    }

    fn version_label(packet: &SflowPacket) -> &'static str {
        match packet {
            SflowPacket::V5(_) => metrics::LABEL_SFLOW_V5,
        }
    }

    fn version_label_of(payload: &[u8]) -> Option<&'static str> {
        match u32::from_be_bytes(payload.get(..4)?.try_into().ok()?) {
            SFLOW_V5_VERSION => Some(metrics::LABEL_SFLOW_V5),
            _ => None,
        }
    }

    fn flow_count(packet: &SflowPacket) -> usize {
        match packet {
            SflowPacket::V5(p) => p
                .samples
                .iter()
                .filter(|s| matches!(s, Sample::Flow(_) | Sample::ExpandedFlow(_)))
                .count(),
        }
    }
}
