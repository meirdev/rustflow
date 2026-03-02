use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use rustc_hash::FxHashMap;
use rustflow_core::common::common_flow::{
    CommonFlow, IpfixContext, NetFlowV5Context, NetFlowV9Context, SFlowV5Context,
    SamplingRateCache, extract_ipfix_sampling_rate, extract_v9_sampling_rate,
};
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::ipfix::parser::{IPFIX_VERSION, IpfixParser, Record as IpfixRecord};
use rustflow_core::netflow_v5::parser::{NETFLOW_V5_VERSION, NetFlowV5Parser};
use rustflow_core::netflow_v9::parser::{NETFLOW_V9_VERSION, NetflowV9Parser, Record as V9Record};
use rustflow_core::sflow_v5::parser::{SFLOW_V5_VERSION, Sample, SflowV5Parser};

/// A reader for NetFlow (v5, v9) and IPFIX data.
pub struct NetflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    ie_registry: IERegistry,
    template_timeout: Duration,
    v5_parser: NetFlowV5Parser,
    v9_parsers: FxHashMap<IpAddr, NetflowV9Parser>,
    ipfix_parsers: FxHashMap<IpAddr, IpfixParser>,
    sampling_cache: SamplingRateCache,
    pending_flows: Vec<CommonFlow>,
}

impl NetflowReader {
    /// Bind to a UDP socket and create a new NetFlow reader.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            ie_registry: IERegistry::new_with_iana_elements(),
            template_timeout: Duration::from_secs(600),
            v5_parser: NetFlowV5Parser::default(),
            v9_parsers: FxHashMap::default(),
            ipfix_parsers: FxHashMap::default(),
            sampling_cache: SamplingRateCache::default(),
            pending_flows: Vec::new(),
        })
    }

    /// Set a custom IE registry.
    pub fn with_ie_registry(mut self, registry: IERegistry) -> Self {
        self.ie_registry = registry;
        self
    }

    /// Set the template cache timeout.
    pub fn with_template_timeout(mut self, timeout: Duration) -> Self {
        self.template_timeout = timeout;
        self
    }

    /// Set a read timeout on the socket.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    /// Get the local address this reader is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Read the next flow from the socket.
    /// Returns `None` if a read timeout occurs.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop() {
            return Ok(Some(flow));
        }

        // Read from socket
        let (len, src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(None),
            Err(e) => return Err(e),
        };

        let src = src_addr.ip();
        let payload = &self.buf[..len];

        if payload.len() < 2 {
            return Ok(None);
        }

        let version = u16::from_be_bytes([payload[0], payload[1]]);
        let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

        match version {
            NETFLOW_V5_VERSION => {
                if let Ok((_, parsed)) = self.v5_parser.parse(payload) {
                    let ctx = NetFlowV5Context {
                        header: &parsed.header,
                        sampler_address: Some(src),
                    };
                    for record in parsed.flow_records.iter().rev() {
                        let mut flow = ctx.convert(record);
                        flow.time_received_ns = time_received_ns;
                        self.pending_flows.push(flow);
                    }
                }
            }
            NETFLOW_V9_VERSION => {
                let parser = self.v9_parsers.entry(src).or_insert_with(|| {
                    NetflowV9Parser::new(self.ie_registry.clone(), self.template_timeout)
                });

                if let Ok((_, parsed)) = parser.parse(payload) {
                    let cache_key = (src, parsed.header.source_id);

                    for flow_set in parsed.flow_sets.iter().rev() {
                        for record in flow_set.records.iter().rev() {
                            if let V9Record::Data(data_record) = record {
                                if let Some(rate) = extract_v9_sampling_rate(data_record) {
                                    self.sampling_cache.set(cache_key, rate);
                                }

                                let ctx = NetFlowV9Context {
                                    header: &parsed.header,
                                    sampler_address: Some(src),
                                    sampling_rate: self.sampling_cache.get(&cache_key),
                                };
                                let mut flow = ctx.convert(data_record, flow_set.id);
                                flow.time_received_ns = time_received_ns;
                                self.pending_flows.push(flow);
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
                    let cache_key = (src, parsed.header.observation_domain_id);

                    for set in parsed.sets.iter().rev() {
                        for record in set.records.iter().rev() {
                            if let IpfixRecord::Data(data_record) = record {
                                if let Some(rate) = extract_ipfix_sampling_rate(data_record) {
                                    self.sampling_cache.set(cache_key, rate);
                                }

                                let ctx = IpfixContext {
                                    header: &parsed.header,
                                    sampler_address: Some(src),
                                    sampling_rate: self.sampling_cache.get(&cache_key),
                                };
                                let mut flow = ctx.convert(data_record, set.id);
                                flow.time_received_ns = time_received_ns;
                                self.pending_flows.push(flow);
                            }
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unknown NetFlow version: {}", version);
            }
        }

        // Return the first pending flow
        Ok(self.pending_flows.pop())
    }
}

impl Iterator for NetflowReader {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Some(flow)) => return Some(Ok(flow)),
                Ok(None) => continue, // timeout or no data, try again
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// A reader for sFlow v5 data.
pub struct SflowReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    parser: SflowV5Parser,
    pending_flows: Vec<CommonFlow>,
}

impl SflowReader {
    /// Bind to a UDP socket and create a new sFlow reader.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
            parser: SflowV5Parser::default(),
            pending_flows: Vec::new(),
        })
    }

    /// Set a read timeout on the socket.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    /// Get the local address this reader is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Read the next flow from the socket.
    /// Returns `None` if a read timeout occurs.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop() {
            return Ok(Some(flow));
        }

        // Read from socket
        let (len, _src_addr) = match self.socket.recv_from(&mut self.buf) {
            Ok(result) => result,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(None),
            Err(e) => return Err(e),
        };

        let payload = &self.buf[..len];

        if payload.len() < 4 {
            return Ok(None);
        }

        let version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let time_received_ns = chrono::Utc::now().timestamp_nanos_opt();

        if version == SFLOW_V5_VERSION {
            if let Ok((_, parsed)) = self.parser.parse(payload) {
                let ctx = SFlowV5Context { header: &parsed };

                for sample in parsed.samples.iter().rev() {
                    match sample {
                        Sample::Flow(flow_sample) => {
                            let mut flow = ctx.convert_flow_sample(flow_sample);
                            flow.time_received_ns = time_received_ns;
                            self.pending_flows.push(flow);
                        }
                        Sample::ExpandedFlow(expanded_sample) => {
                            let mut flow = ctx.convert_expanded_flow_sample(expanded_sample);
                            flow.time_received_ns = time_received_ns;
                            self.pending_flows.push(flow);
                        }
                        _ => {}
                    }
                }
            }
        } else {
            log::warn!("Unknown sFlow version: {}", version);
        }

        // Return the first pending flow
        Ok(self.pending_flows.pop())
    }
}

impl Iterator for SflowReader {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Some(flow)) => return Some(Ok(flow)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
