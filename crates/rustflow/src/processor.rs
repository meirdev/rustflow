use std::net::IpAddr;
use std::time::Duration;

use rustc_hash::FxHashMap;
use rustflow_core::common::common_flow::{
    CommonFlow, IpfixContext, NetFlowV5Context, NetFlowV9Context, SFlowV5Context,
    SamplingRateCache, extract_ipfix_sampling_rate, extract_v9_sampling_rate,
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

/// Enum representing a parsed NetFlow/IPFIX packet.
#[derive(Debug, Clone)]
pub enum NetflowPacket {
    V5(NetFlowV5Packet),
    V9(NetFlowV9Packet),
    Ipfix(IpfixPacket),
}

/// Enum representing a parsed sFlow packet.
#[derive(Debug, Clone)]
pub enum SflowPacket {
    V5(SFlowV5),
}

/// Packet processor for NetFlow (v5, v9) and IPFIX data.
/// Handles parsing, sampling rate extraction, and conversion to CommonFlow.
pub struct NetflowProcessor {
    pub ie_registry: IERegistry,
    pub template_timeout: Duration,
    pub v5_parser: NetFlowV5Parser,
    pub v9_parsers: FxHashMap<IpAddr, NetflowV9Parser>,
    pub ipfix_parsers: FxHashMap<IpAddr, IpfixParser>,
    pub sampling_cache: SamplingRateCache,
}

impl NetflowProcessor {
    pub fn new() -> Self {
        Self {
            ie_registry: IERegistry::new_with_iana_elements(),
            template_timeout: Duration::from_secs(600),
            v5_parser: NetFlowV5Parser,
            v9_parsers: FxHashMap::default(),
            ipfix_parsers: FxHashMap::default(),
            sampling_cache: SamplingRateCache::default(),
        }
    }

    pub fn with_ie_registry(mut self, registry: IERegistry) -> Self {
        self.ie_registry = registry;
        self
    }

    pub fn with_template_timeout(mut self, timeout: Duration) -> Self {
        self.template_timeout = timeout;
        self
    }

    /// Parse a NetFlow/IPFIX packet and return the raw parsed packet.
    /// This also updates template caches and sampling rate caches internally.
    pub fn parse_raw(&mut self, src: IpAddr, payload: &[u8]) -> Option<NetflowPacket> {
        if payload.len() < 2 {
            return None;
        }

        let version = u16::from_be_bytes([payload[0], payload[1]]);

        match version {
            NETFLOW_V5_VERSION => {
                if let Ok((_, parsed)) = self.v5_parser.parse(payload) {
                    Some(NetflowPacket::V5(parsed))
                } else {
                    None
                }
            }
            NETFLOW_V9_VERSION => {
                let parser = self.v9_parsers.entry(src).or_insert_with(|| {
                    NetflowV9Parser::new(self.ie_registry.clone(), self.template_timeout)
                });

                if let Ok((_, parsed)) = parser.parse(payload) {
                    // Update sampling cache from options data
                    let cache_key = (src, parsed.header.source_id);
                    for flow_set in &parsed.flow_sets {
                        for record in &flow_set.records {
                            if let V9Record::OptionsData(data_record) = record
                                && let Some(rate) = extract_v9_sampling_rate(data_record)
                            {
                                self.sampling_cache.set(cache_key, rate);
                            }
                        }
                    }
                    Some(NetflowPacket::V9(parsed))
                } else {
                    None
                }
            }
            IPFIX_VERSION => {
                let parser = self.ipfix_parsers.entry(src).or_insert_with(|| {
                    IpfixParser::new(self.ie_registry.clone(), self.template_timeout)
                });

                if let Ok((_, parsed)) = parser.parse(payload) {
                    // Update sampling cache from options data
                    let cache_key = (src, parsed.header.observation_domain_id);
                    for set in &parsed.sets {
                        for record in &set.records {
                            if let IpfixRecord::OptionsData(data_record) = record
                                && let Some(rate) = extract_ipfix_sampling_rate(data_record)
                            {
                                self.sampling_cache.set(cache_key, rate);
                            }
                        }
                    }
                    Some(NetflowPacket::Ipfix(parsed))
                } else {
                    None
                }
            }
            _ => {
                log::warn!("Unknown NetFlow version: {}", version);
                None
            }
        }
    }

    /// Convert a raw parsed packet to CommonFlow records.
    pub fn convert_to_flows(
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
                let cache_key = (src, parsed.header.source_id);
                let sampling_rate = self.sampling_cache.get(&cache_key);

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
                let cache_key = (src, parsed.header.observation_domain_id);
                let sampling_rate = self.sampling_cache.get(&cache_key);

                for set in parsed.sets.iter() {
                    for record in set.records.iter() {
                        if let IpfixRecord::Data(data_record) = record {
                            let ctx = IpfixContext {
                                header: &parsed.header,
                                sampler_address: Some(src),
                                sampling_rate,
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

    /// Process a NetFlow/IPFIX packet and return flows.
    /// Returns flows in packet order.
    pub fn process(
        &mut self,
        src: IpAddr,
        payload: &[u8],
        time_received_ns: Option<i64>,
    ) -> Vec<CommonFlow> {
        let mut flows = Vec::new();

        if payload.len() < 2 {
            return flows;
        }

        let version = u16::from_be_bytes([payload[0], payload[1]]);

        match version {
            NETFLOW_V5_VERSION => {
                if let Ok((_, parsed)) = self.v5_parser.parse(payload) {
                    flows.reserve(v5_record_count(&parsed));

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
            }
            NETFLOW_V9_VERSION => {
                let parser = self.v9_parsers.entry(src).or_insert_with(|| {
                    NetflowV9Parser::new(self.ie_registry.clone(), self.template_timeout)
                });

                if let Ok((_, parsed)) = parser.parse(payload) {
                    flows.reserve(v9_record_count(&parsed));

                    let cache_key = (src, parsed.header.source_id);
                    let mut sampling_rate = self.sampling_cache.get(&cache_key);

                    for flow_set in parsed.flow_sets.iter() {
                        for record in flow_set.records.iter() {
                            match record {
                                V9Record::OptionsData(data_record) => {
                                    if let Some(rate) = extract_v9_sampling_rate(data_record) {
                                        self.sampling_cache.set(cache_key, rate);
                                        sampling_rate = Some(rate);
                                    }
                                }
                                V9Record::Data(data_record) => {
                                    if let Some(rate) = extract_v9_sampling_rate(data_record) {
                                        self.sampling_cache.set(cache_key, rate);
                                        sampling_rate = Some(rate);
                                    }

                                    let ctx = NetFlowV9Context {
                                        header: &parsed.header,
                                        sampler_address: Some(src),
                                        sampling_rate,
                                    };
                                    let mut flow = ctx.convert(data_record, flow_set.id);
                                    flow.time_received_ns = time_received_ns;
                                    flows.push(flow);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            IPFIX_VERSION => {
                let parser = self.ipfix_parsers.entry(src).or_insert_with(|| {
                    IpfixParser::new(self.ie_registry.clone(), self.template_timeout)
                });

                if let Ok((_, parsed)) = parser.parse(payload) {
                    flows.reserve(ipfix_record_count(&parsed));

                    let cache_key = (src, parsed.header.observation_domain_id);
                    let mut sampling_rate = self.sampling_cache.get(&cache_key);

                    for set in parsed.sets.iter() {
                        for record in set.records.iter() {
                            match record {
                                IpfixRecord::OptionsData(data_record) => {
                                    if let Some(rate) = extract_ipfix_sampling_rate(data_record) {
                                        self.sampling_cache.set(cache_key, rate);
                                        sampling_rate = Some(rate);
                                    }
                                }
                                IpfixRecord::Data(data_record) => {
                                    if let Some(rate) = extract_ipfix_sampling_rate(data_record) {
                                        self.sampling_cache.set(cache_key, rate);
                                        sampling_rate = Some(rate);
                                    }

                                    let ctx = IpfixContext {
                                        header: &parsed.header,
                                        sampler_address: Some(src),
                                        sampling_rate,
                                    };
                                    let mut flow = ctx.convert(data_record, set.id);
                                    flow.time_received_ns = time_received_ns;
                                    flows.push(flow);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unknown NetFlow version: {}", version);
            }
        }

        flows
    }
}

impl Default for NetflowProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet processor for sFlow v5 data.
pub struct SflowProcessor {
    pub parser: SflowV5Parser,
}

impl SflowProcessor {
    pub fn new() -> Self {
        Self {
            parser: SflowV5Parser,
        }
    }

    /// Parse an sFlow packet and return the raw parsed packet.
    pub fn parse_raw(&mut self, payload: &[u8]) -> Option<SflowPacket> {
        if payload.len() < 4 {
            return None;
        }

        let version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if version == SFLOW_V5_VERSION {
            if let Ok((_, parsed)) = self.parser.parse(payload) {
                Some(SflowPacket::V5(parsed))
            } else {
                None
            }
        } else {
            log::warn!("Unknown sFlow version: {}", version);
            None
        }
    }

    /// Convert a raw parsed packet to CommonFlow records.
    pub fn convert_to_flows(
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

    /// Process an sFlow packet and return flows.
    /// Returns flows in packet order.
    pub fn process(&mut self, payload: &[u8], time_received_ns: Option<i64>) -> Vec<CommonFlow> {
        let mut flows = Vec::new();

        if payload.len() < 4 {
            return flows;
        }

        let version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if version == SFLOW_V5_VERSION {
            if let Ok((_, parsed)) = self.parser.parse(payload) {
                let ctx = SFlowV5Context { header: &parsed };

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
        } else {
            log::warn!("Unknown sFlow version: {}", version);
        }

        flows
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
        NetflowPacket::V5(parsed) => v5_record_count(parsed),
        NetflowPacket::V9(parsed) => v9_record_count(parsed),
        NetflowPacket::Ipfix(parsed) => ipfix_record_count(parsed),
    }
}

fn v5_record_count(parsed: &NetFlowV5Packet) -> usize {
    parsed.flow_records.len()
}

fn v9_record_count(parsed: &NetFlowV9Packet) -> usize {
    parsed.flow_sets.iter().map(|s| s.records.len()).sum()
}

fn ipfix_record_count(parsed: &IpfixPacket) -> usize {
    parsed.sets.iter().map(|s| s.records.len()).sum()
}
