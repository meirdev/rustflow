use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::ReadError;
use crate::common_flow::{
    CommonFlow, ExporterOptions, from_ipfix, from_netflow_v5, from_netflow_v9, from_sflow_v5,
};
use crate::information_element::Registry;
use crate::timed_map::BoundedTimedMap;
use crate::{ipfix, netflow_v5, netflow_v9, sflow_v5};

const TEMPLATE_CAPACITY: usize = 4096;
const TEMPLATE_TTL: Duration = Duration::from_mins(30);

const OPTIONS_CAPACITY: usize = 1024;
const MAX_EXPORTERS: usize = 4096;

pub trait Processor {
    type Packet;

    fn parse(
        &mut self,
        from: IpAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<Self::Packet, ReadError>;

    fn convert(
        &mut self,
        from: IpAddr,
        packet: &Self::Packet,
        received_ns: i64,
        now: Instant,
        flows: &mut impl Extend<CommonFlow>,
    );
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "protocol", content = "packet"))]
pub enum NetflowPacket {
    #[cfg_attr(feature = "serde", serde(rename = "netflow_v5"))]
    V5(netflow_v5::Packet),
    #[cfg_attr(feature = "serde", serde(rename = "netflow_v9"))]
    V9(netflow_v9::Packet),
    #[cfg_attr(feature = "serde", serde(rename = "ipfix"))]
    Ipfix(ipfix::Packet),
}

#[derive(Debug)]
pub struct NetflowProcessor {
    registry: Registry,
    template_ttl: Duration,
    exporters: BoundedTimedMap<IpAddr, Exporter>,
}

#[derive(Debug)]
struct Exporter {
    netflow_v9: netflow_v9::Parser,
    ipfix: ipfix::Parser,
    options: ExporterOptions,
}

impl Exporter {
    fn new(registry: &Registry, ttl: Duration) -> Self {
        Self {
            netflow_v9: netflow_v9::Parser::new(
                registry.clone(),
                BoundedTimedMap::new(TEMPLATE_CAPACITY, ttl),
            ),
            ipfix: ipfix::Parser::new(
                registry.clone(),
                BoundedTimedMap::new(TEMPLATE_CAPACITY, ttl),
                BoundedTimedMap::new(OPTIONS_CAPACITY, ttl),
            ),
            options: ExporterOptions::new(OPTIONS_CAPACITY, ttl),
        }
    }
}

impl NetflowProcessor {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            template_ttl: TEMPLATE_TTL,
            exporters: BoundedTimedMap::new(MAX_EXPORTERS, TEMPLATE_TTL),
        }
    }

    pub fn with_template_ttl(mut self, ttl: Duration) -> Self {
        self.template_ttl = ttl;
        self.exporters = BoundedTimedMap::new(MAX_EXPORTERS, ttl);
        self
    }

    fn exporter(&mut self, from: IpAddr, now: Instant) -> &mut Exporter {
        let (registry, ttl) = (&self.registry, self.template_ttl);
        self.exporters
            .get_or_insert_with_at(from, now, || Exporter::new(registry, ttl))
            .expect("the exporter map has room")
    }
}

impl Default for NetflowProcessor {
    fn default() -> Self {
        Self::new(Registry::iana())
    }
}

impl Processor for NetflowProcessor {
    type Packet = NetflowPacket;

    fn parse(
        &mut self,
        from: IpAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<NetflowPacket, ReadError> {
        let version = match *payload {
            [high, low, ..] => u16::from_be_bytes([high, low]),
            _ => return Err(ReadError::Truncated),
        };
        let version = u32::from(version);
        let packet = match version {
            5 => netflow_v5::parse(payload).map(NetflowPacket::V5),
            9 => self
                .exporter(from, now)
                .netflow_v9
                .parse_at(payload, now)
                .map(NetflowPacket::V9),
            10 => self
                .exporter(from, now)
                .ipfix
                .parse_at(payload, now)
                .map(NetflowPacket::Ipfix),
            version => return Err(ReadError::UnknownVersion(version)),
        };
        packet.map_err(|error| ReadError::Parse { version, error })
    }

    fn convert(
        &mut self,
        from: IpAddr,
        packet: &NetflowPacket,
        received_ns: i64,
        now: Instant,
        flows: &mut impl Extend<CommonFlow>,
    ) {
        match packet {
            NetflowPacket::V5(packet) => flows.extend(from_netflow_v5(packet, from, received_ns)),
            NetflowPacket::V9(packet) => {
                let options = &mut self.exporter(from, now).options;
                flows.extend(from_netflow_v9(packet, from, received_ns, options, now));
            }
            NetflowPacket::Ipfix(packet) => {
                let options = &mut self.exporter(from, now).options;
                flows.extend(from_ipfix(packet, from, received_ns, options, now));
            }
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "protocol", content = "packet"))]
pub enum SflowPacket {
    #[cfg_attr(feature = "serde", serde(rename = "sflow_v5"))]
    V5(sflow_v5::Packet),
}

#[derive(Debug, Default)]
pub struct SflowProcessor;

impl Processor for SflowProcessor {
    type Packet = SflowPacket;

    fn parse(
        &mut self,
        _from: IpAddr,
        payload: &[u8],
        _now: Instant,
    ) -> Result<SflowPacket, ReadError> {
        let version = match *payload {
            [a, b, c, d, ..] => u32::from_be_bytes([a, b, c, d]),
            _ => return Err(ReadError::Truncated),
        };
        match version {
            5 => sflow_v5::parse(payload)
                .map(SflowPacket::V5)
                .map_err(|error| ReadError::Parse { version, error }),
            version => Err(ReadError::UnknownVersion(version)),
        }
    }

    fn convert(
        &mut self,
        _from: IpAddr,
        packet: &SflowPacket,
        received_ns: i64,
        _now: Instant,
        flows: &mut impl Extend<CommonFlow>,
    ) {
        match packet {
            SflowPacket::V5(packet) => flows.extend(from_sflow_v5(packet, received_ns)),
        }
    }
}
