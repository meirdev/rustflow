use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use rustflow_core::common::common_flow::CommonFlow;
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::common::utils::parse_udp_packet;

use crate::processor::{NetflowProcessor, SflowProcessor};

fn pcap_ts_to_nanos(ts: std::time::Duration) -> i64 {
    ts.as_nanos() as i64
}

/// A reader for NetFlow (v5, v9) and IPFIX data from pcap files.
pub struct NetflowPcapReader {
    reader: PcapReader<File>,
    processor: NetflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl NetflowPcapReader {
    /// Open a pcap file and create a new NetFlow pcap reader.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = PcapReader::new(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            reader,
            processor: NetflowProcessor::new(),
            pending_flows: VecDeque::new(),
        })
    }

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

    /// Read the next flow from the pcap file.
    /// Returns `None` when the file is exhausted.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop_front() {
            return Ok(Some(flow));
        }

        // Read next packet from pcap
        loop {
            match self.reader.next_packet() {
                Some(Ok(packet)) => {
                    let time_received_ns = Some(pcap_ts_to_nanos(packet.timestamp));

                    if let Ok((src, payload)) = parse_udp_packet(&packet.data) {
                        self.pending_flows.extend(self.processor.process(
                            src,
                            &payload,
                            time_received_ns,
                        ));

                        // Return first pending flow if any
                        if let Some(flow) = self.pending_flows.pop_front() {
                            return Ok(Some(flow));
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                None => return Ok(None), // End of file
            }
        }
    }
}

impl Iterator for NetflowPcapReader {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read() {
            Ok(Some(flow)) => Some(Ok(flow)),
            Ok(None) => None, // End of file
            Err(e) => Some(Err(e)),
        }
    }
}

/// A reader for sFlow v5 data from pcap files.
pub struct SflowPcapReader {
    reader: PcapReader<File>,
    processor: SflowProcessor,
    pending_flows: VecDeque<CommonFlow>,
}

impl SflowPcapReader {
    /// Open a pcap file and create a new sFlow pcap reader.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = PcapReader::new(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            reader,
            processor: SflowProcessor::new(),
            pending_flows: VecDeque::new(),
        })
    }

    /// Read the next flow from the pcap file.
    /// Returns `None` when the file is exhausted.
    pub fn read(&mut self) -> io::Result<Option<CommonFlow>> {
        // Return pending flows first
        if let Some(flow) = self.pending_flows.pop_front() {
            return Ok(Some(flow));
        }

        // Read next packet from pcap
        loop {
            match self.reader.next_packet() {
                Some(Ok(packet)) => {
                    let time_received_ns = Some(pcap_ts_to_nanos(packet.timestamp));

                    if let Ok((_src, payload)) = parse_udp_packet(&packet.data) {
                        self.pending_flows
                            .extend(self.processor.process(&payload, time_received_ns));

                        // Return first pending flow if any
                        if let Some(flow) = self.pending_flows.pop_front() {
                            return Ok(Some(flow));
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                None => return Ok(None), // End of file
            }
        }
    }
}

impl Iterator for SflowPcapReader {
    type Item = io::Result<CommonFlow>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read() {
            Ok(Some(flow)) => Some(Ok(flow)),
            Ok(None) => None, // End of file
            Err(e) => Some(Err(e)),
        }
    }
}
