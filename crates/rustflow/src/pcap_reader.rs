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
use crate::reader::{ReadEvent, ReadResult};

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

    /// Decode with a processor configured by hand. It replaces the current
    /// one, and with it what `with_ie_registry` and `with_template_timeout`
    /// set, so call those after this.
    pub fn with_processor(mut self, processor: P) -> Self {
        self.processor = processor;
        self
    }

    pub fn processor(&self) -> &P {
        &self.processor
    }

    pub fn processor_mut(&mut self) -> &mut P {
        &mut self.processor
    }

    /// Read the next UDP datagram of the file as a raw packet, or
    /// [`ReadResult::End`] when the file is exhausted.
    pub fn read_raw(&mut self) -> io::Result<ReadResult<P>> {
        let link_type = self.reader.header().datalink.into();
        loop {
            let Some(packet) = self.reader.next_packet() else {
                return Ok(ReadResult::End);
            };
            let packet =
                packet.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let Some((src, payload)) = parse_udp_packet(link_type, &packet.data) else {
                continue;
            };
            let len = payload.len();
            return Ok(match self.processor.parse(src, payload) {
                Some(packet) => ReadResult::Packet { len, src, packet },
                None => ReadResult::ParseError {
                    len,
                    src,
                    version: P::version_of(payload),
                },
            });
        }
    }

    /// Read the next flow from the pcap file, or [`ReadEvent::End`] when the
    /// file is exhausted.
    pub fn read(&mut self) -> io::Result<ReadEvent> {
        loop {
            if let Some(flow) = self.pending_flows.pop_front() {
                return Ok(ReadEvent::Flow(Box::new(flow)));
            }
            let link_type = self.reader.header().datalink.into();
            match self.reader.next_packet() {
                Some(Ok(packet)) => {
                    let time_received_ns = i64::try_from(packet.timestamp.as_nanos()).ok();
                    if let Some((src, payload)) = parse_udp_packet(link_type, &packet.data) {
                        self.processor.process_into(
                            src,
                            payload,
                            time_received_ns,
                            &mut self.pending_flows,
                        );
                    }
                }
                Some(Err(e)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                None => return Ok(ReadEvent::End),
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
        loop {
            match self.read() {
                Ok(ReadEvent::Flow(flow)) => return Some(Ok(*flow)),
                Ok(ReadEvent::Timeout) => continue,
                Ok(ReadEvent::End) => return None,
                Err(e) => return Some(Err(e)),
            }
        }
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
    fn read_raw_yields_every_datagram_then_the_end() {
        use crate::processor::Packet;

        let mut reader = NetflowPcapReader::open(fixture("netflow_v5")).unwrap();
        let mut flows = 0;
        loop {
            match reader.read_raw().unwrap() {
                ReadResult::Packet { packet, .. } => flows += packet.flow_count(),
                ReadResult::End => break,
                ReadResult::ParseError { .. } | ReadResult::Timeout => {
                    panic!("expected a packet or the end")
                }
            }
        }
        assert_eq!(flows, 10);
        assert!(matches!(reader.read_raw().unwrap(), ReadResult::End));
        assert!(matches!(reader.read().unwrap(), ReadEvent::End));
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
