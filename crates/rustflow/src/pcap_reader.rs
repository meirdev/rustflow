use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::common::packet::parse_udp_packet;

use crate::processor::{NetflowProcessor, Processor, SflowProcessor};

/// Reads one protocol family from the UDP datagrams of a pcap file, with
/// the capture time as the receive time.
pub struct Reader<P: Processor> {
    reader: PcapReader<File>,
    processor: P,
    pending_flows: VecDeque<CommonFlow>,
}

/// A reader for NetFlow (v5, v9) and IPFIX data from pcap files.
pub type NetflowPcapReader = Reader<NetflowProcessor>;

/// A reader for sFlow v5 data from pcap files.
pub type SflowPcapReader = Reader<SflowProcessor>;

impl<P: Processor> Reader<P> {
    /// Open a pcap file.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let reader = PcapReader::new(File::open(path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            reader,
            processor: P::default(),
            pending_flows: VecDeque::new(),
        })
    }

    /// Decode with a processor configured by hand.
    pub fn with_processor(mut self, processor: P) -> Self {
        self.processor = processor;
        self
    }

    /// Read the next flow from the pcap file.
    /// Returns `None` when the file is exhausted.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        loop {
            if let Some(flow) = self.pending_flows.pop_front() {
                return Ok(Some(flow));
            }
            let link_type = self.reader.header().datalink.into();
            match self.reader.next_packet() {
                Some(Ok(packet)) => {
                    let time_received_ns = Some(packet.timestamp.as_nanos() as i64);
                    if let Some((src, payload)) = parse_udp_packet(link_type, &packet.data) {
                        self.pending_flows.extend(self.processor.process(
                            src,
                            &payload,
                            time_received_ns,
                        ));
                    }
                }
                Some(Err(e)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                None => return Ok(None),
            }
        }
    }
}

impl Reader<NetflowProcessor> {
    /// Set a custom IE registry.
    pub fn with_ie_registry(mut self, registry: IERegistry) -> Self {
        self.processor = self.processor.with_ie_registry(registry);
        self
    }

    /// Set the template cache timeout.
    pub fn with_template_timeout(mut self, timeout: Duration) -> Self {
        self.processor = self.processor.with_template_timeout(timeout);
        self
    }
}

impl<P: Processor> Iterator for Reader<P> {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        format!(
            "{}/../../tests/fixtures/pcap/{name}_sanity.pcap",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn pcap_readers_yield_every_flow_of_the_fixtures() {
        for (name, flows) in [("netflow_v5", 10), ("netflow_v9", 10), ("ipfix", 10)] {
            let reader = NetflowPcapReader::open(fixture(name)).unwrap();
            assert_eq!(reader.map(Result::unwrap).count(), flows, "{name}");
        }
        let reader = SflowPcapReader::open(fixture("sflow_v5")).unwrap();
        assert_eq!(reader.map(Result::unwrap).count(), 12);
    }
}
