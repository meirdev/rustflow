use std::net::IpAddr;
use std::time::{Duration, Instant};

use jiff::Timestamp;

use super::{ReadError, nanoseconds};
use crate::common_flow::{
    CommonFlow, ExporterOptions, ExtraFields, FlowType, extend_with_extra, from_ipfix,
    from_netflow_v5, from_netflow_v9, from_sflow_v5,
};
use crate::information_element::Registry;
use crate::set::Set;
use crate::sflow_v5::Sample;
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

    /// What a packet holds.
    fn summary(packet: &Self::Packet) -> Summary;

    /// Parses a datagram and adds its flows to `flows`, in one step.
    fn process(
        &mut self,
        from: IpAddr,
        payload: &[u8],
        received: Timestamp,
        now: Instant,
        flows: &mut impl Extend<CommonFlow>,
    ) -> Result<Summary, ReadError> {
        let packet = self.parse(from, payload, now)?;
        self.convert(from, &packet, nanoseconds(received), now, flows);
        Ok(Self::summary(&packet))
    }
}

/// What one datagram held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Summary {
    pub flow_type: FlowType,
    /// The flows it carries: one for each data record or flow sample.
    pub flows: usize,
    /// The data sets it could not decode, for lack of a template that
    /// matches them. How many records they held is not known.
    pub undecoded_sets: usize,
}

impl Summary {
    pub fn new(flow_type: FlowType, flows: usize) -> Self {
        Self {
            flow_type,
            flows,
            undecoded_sets: 0,
        }
    }

    pub fn with_undecoded_sets(mut self, undecoded_sets: usize) -> Self {
        self.undecoded_sets = undecoded_sets;
        self
    }
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

impl NetflowPacket {
    pub fn flow_type(&self) -> FlowType {
        match self {
            Self::V5(_) => FlowType::NetflowV5,
            Self::V9(_) => FlowType::NetflowV9,
            Self::Ipfix(_) => FlowType::Ipfix,
        }
    }

    pub fn flow_count(&self) -> usize {
        match self {
            Self::V5(packet) => packet.flow_records.len(),
            Self::V9(packet) => data_records(&packet.flow_sets),
            Self::Ipfix(packet) => data_records(&packet.sets),
        }
    }

    pub fn undecoded_sets(&self) -> usize {
        match self {
            Self::V5(_) => 0,
            Self::V9(packet) => undecoded(&packet.flow_sets),
            Self::Ipfix(packet) => undecoded(&packet.sets),
        }
    }
}

fn data_records<S>(sets: &[Set<S>]) -> usize {
    sets.iter()
        .filter_map(Set::as_data)
        .map(|set| set.records.len())
        .sum()
}

fn undecoded<S>(sets: &[Set<S>]) -> usize {
    sets.iter()
        .filter(|set| matches!(set, Set::Undecoded { .. }))
        .count()
}

#[derive(Debug)]
pub struct NetflowProcessor {
    registry: Registry,
    template_ttl: Duration,
    exporters: BoundedTimedMap<IpAddr, Exporter>,
    extra_fields: ExtraFields,
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
            extra_fields: ExtraFields::default(),
        }
    }

    /// Copies these elements of each NetFlow v9 and IPFIX data record into
    /// [`CommonFlow::extra`].
    pub fn with_extra_fields(mut self, extra_fields: ExtraFields) -> Self {
        self.extra_fields = extra_fields;
        self
    }

    pub fn extra_fields(&self) -> &ExtraFields {
        &self.extra_fields
    }

    pub fn with_template_ttl(mut self, ttl: Duration) -> Self {
        self.template_ttl = ttl;
        self.exporters = BoundedTimedMap::new(MAX_EXPORTERS, ttl);
        self
    }

    fn exporter(&mut self, from: IpAddr, now: Instant) -> &mut Exporter {
        exporter(
            &mut self.exporters,
            &self.registry,
            self.template_ttl,
            from,
            now,
        )
    }
}

fn exporter<'a>(
    exporters: &'a mut BoundedTimedMap<IpAddr, Exporter>,
    registry: &Registry,
    ttl: Duration,
    from: IpAddr,
    now: Instant,
) -> &'a mut Exporter {
    exporters
        .get_or_insert_with_at(from, now, || Exporter::new(registry, ttl))
        .expect("the exporter map has room")
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
        let (flow_type, packet) = match version {
            5 => (
                FlowType::NetflowV5,
                netflow_v5::parse(payload).map(NetflowPacket::V5),
            ),
            9 => (
                FlowType::NetflowV9,
                self.exporter(from, now)
                    .netflow_v9
                    .parse_at(payload, now)
                    .map(NetflowPacket::V9),
            ),
            10 => (
                FlowType::Ipfix,
                self.exporter(from, now)
                    .ipfix
                    .parse_at(payload, now)
                    .map(NetflowPacket::Ipfix),
            ),
            version => return Err(ReadError::UnknownVersion(version.into())),
        };
        packet.map_err(|error| ReadError::Parse { flow_type, error })
    }

    fn convert(
        &mut self,
        from: IpAddr,
        packet: &NetflowPacket,
        received_ns: i64,
        now: Instant,
        flows: &mut impl Extend<CommonFlow>,
    ) {
        let Self {
            registry,
            template_ttl,
            exporters,
            extra_fields,
        } = self;
        match packet {
            NetflowPacket::V5(packet) => flows.extend(from_netflow_v5(packet, from, received_ns)),
            NetflowPacket::V9(packet) => {
                let options = &mut exporter(exporters, registry, *template_ttl, from, now).options;
                let converted = from_netflow_v9(packet, from, received_ns, options, now);
                extend_with_extra(flows, converted, &packet.flow_sets, extra_fields);
            }
            NetflowPacket::Ipfix(packet) => {
                let options = &mut exporter(exporters, registry, *template_ttl, from, now).options;
                let converted = from_ipfix(packet, from, received_ns, options, now);
                extend_with_extra(flows, converted, &packet.sets, extra_fields);
            }
        }
    }

    fn summary(packet: &NetflowPacket) -> Summary {
        Summary::new(packet.flow_type(), packet.flow_count())
            .with_undecoded_sets(packet.undecoded_sets())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "protocol", content = "packet"))]
pub enum SflowPacket {
    #[cfg_attr(feature = "serde", serde(rename = "sflow_v5"))]
    V5(sflow_v5::Packet),
}

impl SflowPacket {
    pub fn flow_type(&self) -> FlowType {
        match self {
            Self::V5(_) => FlowType::SflowV5,
        }
    }

    pub fn flow_count(&self) -> usize {
        match self {
            Self::V5(packet) => packet
                .samples
                .iter()
                .filter(|sample| matches!(sample, Sample::Flow(_) | Sample::ExpandedFlow(_)))
                .count(),
        }
    }
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
                .map_err(|error| ReadError::Parse {
                    flow_type: FlowType::SflowV5,
                    error,
                }),
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

    fn summary(packet: &SflowPacket) -> Summary {
        Summary::new(packet.flow_type(), packet.flow_count())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::information_element::ElementId;
    use crate::value::Value;

    const FIELDS: [u8; 12] = [
        0, 8, 0, 4, // sourceIPv4Address
        0, 1, 0, 4, // octetDeltaCount
        0, 252, 0, 4, // ingressPhysicalInterface
    ];
    const RECORDS: [u8; 24] = [
        192, 0, 2, 1, 0, 0, 0, 100, 0, 0, 0, 5, // a record
        192, 0, 2, 2, 0, 0, 0, 200, 0, 0, 0, 6, // a record
    ];

    fn set(id: u16, body: &[&[u8]]) -> Vec<u8> {
        let body = body.concat();
        let length = u16::try_from(4 + body.len()).unwrap();
        [&id.to_be_bytes()[..], &length.to_be_bytes(), &body].concat()
    }

    fn ipfix() -> Vec<u8> {
        let template = set(2, &[&[1, 0, 0, 3], &FIELDS]);
        let sets = [template, set(256, &[&RECORDS])].concat();
        let length = u16::try_from(16 + sets.len()).unwrap();
        [&[0, 10][..], &length.to_be_bytes(), &[0; 12], &sets].concat()
    }

    fn netflow_v9() -> Vec<u8> {
        let template = set(0, &[&[1, 0, 0, 3], &FIELDS]);
        let flow_sets = [template, set(256, &[&RECORDS])].concat();
        [&[0, 9, 0, 3][..], &[0; 16], &flow_sets].concat()
    }

    fn flows(processor: &mut NetflowProcessor, payload: &[u8]) -> Vec<CommonFlow> {
        let mut flows = Vec::new();
        let from = [192, 0, 2, 9].into();
        let received = Timestamp::UNIX_EPOCH;
        processor
            .process(from, payload, received, Instant::now(), &mut flows)
            .unwrap();
        flows
    }

    #[test]
    fn extra_fields_take_the_values_of_each_record() {
        let extra = ExtraFields::new([
            ElementId::INGRESS_PHYSICAL_INTERFACE,
            ElementId::SOURCE_IPV4_ADDRESS,
            ElementId::SOURCE_TRANSPORT_PORT,
        ]);
        for payload in [ipfix(), netflow_v9()] {
            let mut processor = NetflowProcessor::default().with_extra_fields(extra.clone());
            let flows = flows(&mut processor, &payload);

            let extra: Vec<_> = flows.iter().map(|flow| flow.extra.as_slice()).collect();
            assert_eq!(
                extra,
                [
                    [
                        Some(Value::Unsigned32(5)),
                        Some(Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))),
                        None,
                    ],
                    [
                        Some(Value::Unsigned32(6)),
                        Some(Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 2))),
                        None,
                    ],
                ]
            );
            assert_eq!(flows[1].bytes, Some(200));
        }
    }

    #[test]
    fn without_extra_fields_the_flows_have_none() {
        let flows = flows(&mut NetflowProcessor::default(), &ipfix());

        assert_eq!(flows.len(), 2);
        assert!(flows.iter().all(|flow| flow.extra.is_empty()));
    }
}
