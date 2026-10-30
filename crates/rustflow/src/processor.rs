use std::net::IpAddr;
use std::time::{Duration, Instant};

use log::warn;
use rustc_hash::FxHashMap;
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::convert::{
    IpfixContext, NetFlowV5Context, NetFlowV9Context, SFlowV5Context, extract_ipfix_sampling_rate,
    extract_ipfix_system_init_time, extract_v9_sampling_rate,
};
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::ipfix::parser::{
    IPFIX_VERSION, IpfixPacket, IpfixParser, Record as IpfixRecord,
};
use rustflow_core::netflow_v5::parser::{NETFLOW_V5_VERSION, NetFlowV5Packet, NetFlowV5Parser};
use rustflow_core::netflow_v9::parser::{
    NETFLOW_V9_VERSION, NetFlowV9Packet, NetflowV9Parser, Record as V9Record,
};
use rustflow_core::sflow_v5::parser::{SFLOW_V5_VERSION, SFlowV5, Sample, SflowV5Parser};
use serde::Serialize;

/// Decodes one family of flow protocols: parses datagrams, keeping the
/// state the protocol needs between them, such as templates and sampling
/// rates per exporter, and turns parsed packets into [`CommonFlow`]s.
pub trait Processor: Default {
    type Packet: Packet;

    /// The family's name, `netflow` or `sflow`.
    const NAME: &'static str;

    /// Parses a datagram from exporter `src`, updating the state it
    /// carries. `None` for an unknown version or a malformed packet.
    fn parse(&mut self, src: IpAddr, payload: &[u8]) -> Option<Self::Packet>;

    /// The packet's data records as normalized flows, in packet order.
    fn convert(
        &self,
        src: IpAddr,
        packet: &Self::Packet,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow>;

    /// The version name in a datagram's header, such as `netflow_v9`;
    /// `None` for an unknown version or a truncated header.
    fn version_of(payload: &[u8]) -> Option<&'static str>;

    /// Parses and converts in one step; a packet that fails to parse
    /// yields no flows.
    fn process(
        &mut self,
        src: IpAddr,
        payload: &[u8],
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        self.parse(src, payload)
            .map(|packet| self.convert(src, &packet, time_received_ns))
            .unwrap_or_default()
    }
}

/// A parsed packet of some protocol version, in its original structure.
pub trait Packet: Serialize {
    /// The version name, such as `netflow_v9`.
    fn version(&self) -> &'static str;

    /// The data records, or flow samples, the packet carries.
    fn flow_count(&self) -> usize;
}

pub const NETFLOW: &str = "netflow";
pub const NETFLOW_V5: &str = "netflow_v5";
pub const NETFLOW_V9: &str = "netflow_v9";
pub const IPFIX: &str = "ipfix";
pub const SFLOW: &str = "sflow";
pub const SFLOW_V5: &str = "sflow_v5";

/// A parsed NetFlow v5, NetFlow v9 or IPFIX packet. Serializes as the
/// packet itself, without a version wrapper.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum NetflowPacket {
    V5(NetFlowV5Packet),
    V9(NetFlowV9Packet),
    Ipfix(IpfixPacket),
}

impl Packet for NetflowPacket {
    fn version(&self) -> &'static str {
        match self {
            Self::V5(_) => NETFLOW_V5,
            Self::V9(_) => NETFLOW_V9,
            Self::Ipfix(_) => IPFIX,
        }
    }

    fn flow_count(&self) -> usize {
        match self {
            Self::V5(p) => p.flow_records.len(),
            Self::V9(p) => p
                .flow_sets
                .iter()
                .flat_map(|set| &set.records)
                .filter(|record| matches!(record, V9Record::Data(_)))
                .count(),
            Self::Ipfix(p) => p
                .sets
                .iter()
                .flat_map(|set| &set.records)
                .filter(|record| matches!(record, IpfixRecord::Data(_)))
                .count(),
        }
    }
}

/// A parsed sFlow v5 packet.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SflowPacket {
    V5(SFlowV5),
}

impl Packet for SflowPacket {
    fn version(&self) -> &'static str {
        match self {
            Self::V5(_) => SFLOW_V5,
        }
    }

    fn flow_count(&self) -> usize {
        match self {
            Self::V5(p) => p
                .samples
                .iter()
                .filter(|sample| matches!(sample, Sample::Flow(_) | Sample::ExpandedFlow(_)))
                .count(),
        }
    }
}

/// How often exporters gone quiet are looked for.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// What the options records of one observation domain (source ID in v9)
/// said.
#[derive(Clone, Copy, Default)]
struct Domain {
    sampling_rate: Option<u32>,
    system_init_time_ms: Option<i64>,
}

/// One exporter address: its template cache and its domains.
struct Exporter<P> {
    parser: P,
    domains: FxHashMap<u32, Domain>,
    last_seen: Instant,
}

/// The exporters of one protocol version. One not heard from for the
/// template timeout is forgotten: by then its templates have expired too.
struct Exporters<P> {
    map: FxHashMap<IpAddr, Exporter<P>>,
    next_sweep: Instant,
}

impl<P> Exporters<P> {
    fn new() -> Self {
        Self {
            map: FxHashMap::default(),
            next_sweep: Instant::now(),
        }
    }

    /// The exporter at `src`, marked as seen at `now`; `new` makes its
    /// parser on first contact. Exporters quiet for `timeout` are swept out
    /// along the way.
    fn entry(
        &mut self,
        src: IpAddr,
        now: Instant,
        timeout: Duration,
        new: impl FnOnce() -> P,
    ) -> &mut Exporter<P> {
        if now >= self.next_sweep {
            self.map
                .retain(|_, exporter| now.duration_since(exporter.last_seen) < timeout);
            self.next_sweep = now + SWEEP_INTERVAL;
        }
        let exporter = self.map.entry(src).or_insert_with(|| Exporter {
            parser: new(),
            domains: FxHashMap::default(),
            last_seen: now,
        });
        exporter.last_seen = now;
        exporter
    }

    fn domain(&self, src: IpAddr, id: u32) -> Domain {
        self.map
            .get(&src)
            .and_then(|exporter| exporter.domains.get(&id))
            .copied()
            .unwrap_or_default()
    }
}

/// Packet processor for NetFlow (v5, v9) and IPFIX data.
/// Handles parsing, sampling rate extraction, and conversion to CommonFlow.
pub struct NetflowProcessor {
    ie_registry: IERegistry,
    template_timeout: Duration,
    v5_parser: NetFlowV5Parser,
    v9: Exporters<NetflowV9Parser>,
    ipfix: Exporters<IpfixParser>,
}

impl NetflowProcessor {
    pub fn new() -> Self {
        Self {
            ie_registry: IERegistry::new_with_iana_elements(),
            template_timeout: Duration::from_secs(600),
            v5_parser: NetFlowV5Parser,
            v9: Exporters::new(),
            ipfix: Exporters::new(),
        }
    }

    pub fn with_ie_registry(mut self, registry: IERegistry) -> Self {
        self.ie_registry = registry;
        self
    }

    /// How long templates are kept, and exporters that go quiet.
    pub fn with_template_timeout(mut self, timeout: Duration) -> Self {
        self.template_timeout = timeout;
        self
    }
}

impl Processor for NetflowProcessor {
    type Packet = NetflowPacket;

    const NAME: &'static str = NETFLOW;

    fn parse(&mut self, src: IpAddr, payload: &[u8]) -> Option<NetflowPacket> {
        let version = u16::from_be_bytes(payload.get(..2)?.try_into().ok()?);
        let timeout = self.template_timeout;

        match version {
            NETFLOW_V5_VERSION => {
                let (_, parsed) = self.v5_parser.parse(payload).ok()?;
                Some(NetflowPacket::V5(parsed))
            }
            NETFLOW_V9_VERSION => {
                let exporter = self.v9.entry(src, Instant::now(), timeout, || {
                    NetflowV9Parser::new(self.ie_registry.clone(), timeout)
                });
                let (_, parsed) = exporter.parser.parse(payload).ok()?;
                let domain = exporter.domains.entry(parsed.header.source_id).or_default();
                for record in parsed.flow_sets.iter().flat_map(|set| &set.records) {
                    if let V9Record::OptionsData(data_record) = record
                        && let Some(rate) = extract_v9_sampling_rate(data_record)
                    {
                        domain.sampling_rate = Some(rate);
                    }
                }
                Some(NetflowPacket::V9(parsed))
            }
            IPFIX_VERSION => {
                let exporter = self.ipfix.entry(src, Instant::now(), timeout, || {
                    IpfixParser::new(self.ie_registry.clone(), timeout)
                });
                let (_, parsed) = exporter.parser.parse(payload).ok()?;
                let domain = exporter
                    .domains
                    .entry(parsed.header.observation_domain_id)
                    .or_default();
                for record in parsed.sets.iter().flat_map(|set| &set.records) {
                    if let IpfixRecord::OptionsData(data_record) = record {
                        if let Some(rate) = extract_ipfix_sampling_rate(data_record) {
                            domain.sampling_rate = Some(rate);
                        }
                        if let Some(boot) = extract_ipfix_system_init_time(data_record) {
                            domain.system_init_time_ms = Some(boot);
                        }
                    }
                }
                Some(NetflowPacket::Ipfix(parsed))
            }
            _ => {
                warn!("Unknown NetFlow version: {}", version);
                None
            }
        }
    }

    fn convert(
        &self,
        src: IpAddr,
        packet: &NetflowPacket,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        let mut flows = Vec::with_capacity(estimated_flow_count(packet));

        match packet {
            NetflowPacket::V5(parsed) => {
                let ctx = NetFlowV5Context {
                    header: &parsed.header,
                    sampler_address: Some(src),
                };
                for record in parsed.flow_records.iter() {
                    let mut flow = ctx.convert(record);
                    flow.time_received_ns = time_received_ns;
                    flows.push(flow);
                }
            }
            NetflowPacket::V9(parsed) => {
                let sampling_rate = self.v9.domain(src, parsed.header.source_id).sampling_rate;

                for flow_set in parsed.flow_sets.iter() {
                    for record in flow_set.records.iter() {
                        if let V9Record::Data(data_record) = record {
                            let ctx = NetFlowV9Context {
                                header: &parsed.header,
                                sampler_address: Some(src),
                                sampling_rate,
                            };
                            let mut flow = ctx.convert(data_record, flow_set.id);
                            flow.time_received_ns = time_received_ns;
                            flows.push(flow);
                        }
                    }
                }
            }
            NetflowPacket::Ipfix(parsed) => {
                let Domain {
                    sampling_rate,
                    system_init_time_ms,
                } = self.ipfix.domain(src, parsed.header.observation_domain_id);

                for set in parsed.sets.iter() {
                    for record in set.records.iter() {
                        if let IpfixRecord::Data(data_record) = record {
                            let ctx = IpfixContext {
                                header: &parsed.header,
                                sampler_address: Some(src),
                                sampling_rate,
                                system_init_time_ms,
                            };
                            let mut flow = ctx.convert(data_record, set.id);
                            flow.time_received_ns = time_received_ns;
                            flows.push(flow);
                        }
                    }
                }
            }
        }

        flows
    }

    fn version_of(payload: &[u8]) -> Option<&'static str> {
        match u16::from_be_bytes(payload.get(..2)?.try_into().ok()?) {
            NETFLOW_V5_VERSION => Some(NETFLOW_V5),
            NETFLOW_V9_VERSION => Some(NETFLOW_V9),
            IPFIX_VERSION => Some(IPFIX),
            _ => None,
        }
    }
}

impl Default for NetflowProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet processor for sFlow v5 data.
pub struct SflowProcessor {
    parser: SflowV5Parser,
}

impl SflowProcessor {
    pub fn new() -> Self {
        Self {
            parser: SflowV5Parser,
        }
    }
}

impl Processor for SflowProcessor {
    type Packet = SflowPacket;

    const NAME: &'static str = SFLOW;

    fn parse(&mut self, _src: IpAddr, payload: &[u8]) -> Option<SflowPacket> {
        let version = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?);
        if version != SFLOW_V5_VERSION {
            warn!("Unknown sFlow version: {}", version);
            return None;
        }
        let (_, parsed) = self.parser.parse(payload).ok()?;
        Some(SflowPacket::V5(parsed))
    }

    /// sFlow samples carry their exporter inside, so `src` is not needed.
    fn convert(
        &self,
        _src: IpAddr,
        packet: &SflowPacket,
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        let mut flows = Vec::new();

        match packet {
            SflowPacket::V5(parsed) => {
                let ctx = SFlowV5Context { header: parsed };
                for sample in parsed.samples.iter() {
                    match sample {
                        Sample::Flow(flow_sample) => {
                            let mut flow = ctx.convert_flow_sample(flow_sample);
                            flow.time_received_ns = time_received_ns;
                            flows.push(flow);
                        }
                        Sample::ExpandedFlow(expanded_sample) => {
                            let mut flow = ctx.convert_expanded_flow_sample(expanded_sample);
                            flow.time_received_ns = time_received_ns;
                            flows.push(flow);
                        }
                        _ => {}
                    }
                }
            }
        }

        flows
    }

    fn version_of(payload: &[u8]) -> Option<&'static str> {
        match u32::from_be_bytes(payload.get(..4)?.try_into().ok()?) {
            SFLOW_V5_VERSION => Some(SFLOW_V5),
            _ => None,
        }
    }
}

impl Default for SflowProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Upper bound on the flows a parsed packet yields, used to size the output
/// vector up front.
fn estimated_flow_count(packet: &NetflowPacket) -> usize {
    match packet {
        NetflowPacket::V5(parsed) => parsed.flow_records.len(),
        NetflowPacket::V9(parsed) => parsed.flow_sets.iter().map(|s| s.records.len()).sum(),
        NetflowPacket::Ipfix(parsed) => parsed.sets.iter().map(|s| s.records.len()).sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exporters_gone_quiet_for_the_timeout_are_forgotten() {
        let timeout = Duration::from_secs(60);
        let a: IpAddr = [192, 0, 2, 1].into();
        let b: IpAddr = [192, 0, 2, 2].into();
        let t0 = Instant::now();
        let mut exporters = Exporters::new();

        exporters.entry(a, t0, timeout, || ()).domains.insert(
            1,
            Domain {
                sampling_rate: Some(100),
                system_init_time_ms: None,
            },
        );
        exporters.entry(b, t0, timeout, || ());
        assert_eq!(exporters.map.len(), 2);

        let later = t0 + timeout - SWEEP_INTERVAL;
        exporters.entry(a, later, timeout, || ());
        assert_eq!(exporters.map.len(), 2);

        exporters.entry(a, t0 + timeout, timeout, || ());
        assert_eq!(exporters.map.len(), 1);
        assert_eq!(exporters.domain(a, 1).sampling_rate, Some(100));
        assert_eq!(exporters.domain(b, 1).sampling_rate, None);
    }
}
