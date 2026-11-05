//! Datagrams to records, with the state each exporter's protocols need
//! between datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustflow_convert::{Received, Record, ipfix, netflow_v5, netflow_v9, sflow_v5};
use rustflow_protocol::ParseError;
use rustflow_protocol::information_element::Registry;

/// Exporters one collector may keep state for; the network decides how
/// many send to it.
const MAX_EXPORTERS: usize = 65_536;

/// Turns datagrams into records. One parser and converter per protocol
/// serve each exporter transport address: templates and options are
/// scoped by transport session, as RFC 7011 requires, so two exporting
/// processes on one host are told apart by their ports. An exporter not heard
/// from for the template timeout is forgotten, its templates having expired by
/// then; datagrams of a new exporter past [`MAX_EXPORTERS`] are dropped.
pub struct Collector {
    registry: Registry,
    timeout: Duration,
    exporters: HashMap<SocketAddr, Exporter>,
    next_sweep: Instant,
}

#[derive(Default)]
struct Exporter {
    last_seen: Option<Instant>,
    netflow_v9: Option<(rustflow_protocol::netflow_v9::Parser, netflow_v9::Converter)>,
    ipfix: Option<(rustflow_protocol::ipfix::Parser, ipfix::Converter)>,
}

impl Collector {
    /// Fields are looked up in `registry`. A template expires `timeout`
    /// after it was last received.
    pub fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            registry,
            timeout,
            exporters: HashMap::new(),
            next_sweep: Instant::now() + timeout,
        }
    }

    /// Converts a datagram's records, adding them to `records` in datagram
    /// order. The protocol is read from the datagram: NetFlow and IPFIX
    /// put their version in the first two bytes, sFlow in the first four.
    pub fn collect(
        &mut self,
        received: Received,
        datagram: &[u8],
        records: &mut impl Extend<Record>,
    ) -> Result<(), ParseError> {
        let version = match datagram {
            [0, 0, ..] => rustflow_protocol::sflow_v5::VERSION,
            [high, low, ..] => u32::from(u16::from_be_bytes([*high, *low])),
            _ => 0,
        };
        let (registry, timeout) = (&self.registry.clone(), self.timeout);
        match version {
            5 => netflow_v5::convert(
                rustflow_protocol::netflow_v5::parse(datagram)?,
                &received,
                records,
            ),
            9 => {
                let Some(exporter) = self.exporter(received.exporter) else {
                    return Ok(());
                };
                let (parser, converter) = exporter.netflow_v9.get_or_insert_with(|| {
                    (
                        rustflow_protocol::netflow_v9::Parser::new(registry.clone(), timeout),
                        netflow_v9::Converter::default(),
                    )
                });
                converter.convert(parser.parse(datagram)?, &received, records);
            }
            10 => {
                let Some(exporter) = self.exporter(received.exporter) else {
                    return Ok(());
                };
                let (parser, converter) = exporter.ipfix.get_or_insert_with(|| {
                    (
                        rustflow_protocol::ipfix::Parser::new(registry.clone(), timeout),
                        ipfix::Converter::default(),
                    )
                });
                converter.convert(parser.parse(datagram)?, &received, records);
            }
            _ => sflow_v5::convert(
                rustflow_protocol::sflow_v5::parse(datagram)?,
                &received,
                records,
            ),
        }
        Ok(())
    }

    /// The exporter's state, marked as heard from now; `None` for a new
    /// exporter past [`MAX_EXPORTERS`].
    fn exporter(&mut self, address: SocketAddr) -> Option<&mut Exporter> {
        let now = Instant::now();
        let new = !self.exporters.contains_key(&address);
        if now >= self.next_sweep || (new && self.exporters.len() >= MAX_EXPORTERS) {
            let timeout = self.timeout;
            self.exporters
                .retain(|_, exporter| exporter.last_seen.is_some_and(|seen| now - seen < timeout));
            self.next_sweep = now + timeout;
        }
        if new && self.exporters.len() >= MAX_EXPORTERS {
            return None;
        }
        let exporter = self.exporters.entry(address).or_default();
        exporter.last_seen = Some(now);
        Some(exporter)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new(Registry::iana(), Duration::from_mins(10))
    }
}
