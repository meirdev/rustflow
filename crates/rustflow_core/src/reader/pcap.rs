//! Records from a capture of the datagrams exporters sent, as a collector
//! receiving them would have read them.

use std::fs::File;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use pcap_file::PcapError;
use pcap_file::pcap::PcapReader as PcapFile;

use crate::convert::{Received, Record};
use crate::dissect::udp_payload;
use crate::protocol::Family;
use crate::reader::queue::Queue;
use crate::reader::read::{Flows, Read};
use crate::reader::{Collector, OptionsTable};

/// Reads records from a pcap capture, whatever protocol each datagram is
/// in, as a [`Reader`](crate::reader::Reader) reads them from a socket.
///
/// A datagram's receive time is when it was captured. Frames that are not a
/// whole UDP datagram, such as other traffic or a truncated or fragmented
/// datagram, are read past. Templates still expire by the clock, not by
/// capture time, so a capture read faster than it was made keeps them
/// longer than its exporters meant.
pub struct PcapReader<R: io::Read = File> {
    pcap: PcapFile<R>,
    link_type: u32,
    queue: Queue,
    ended: bool,
}

impl PcapReader {
    /// Reads `family` from the capture at `path`, with the usual registry
    /// and template timeout; see [`PcapReader::new`] for others.
    pub fn open(path: impl AsRef<Path>, family: Family) -> io::Result<Self> {
        Self::new(File::open(path)?, Collector::of(family))
    }
}

impl<R: io::Read> PcapReader<R> {
    pub fn new(capture: R, collector: Collector) -> io::Result<Self> {
        let pcap = PcapFile::new(capture).map_err(io_error)?;
        let link_type = pcap.header().datalink.into();
        Ok(Self {
            pcap,
            link_type,
            queue: Queue::new(collector),
            ended: false,
        })
    }

    /// The latest options records read, by exporter, domain and scope.
    pub fn options(&self) -> OptionsTable<'_> {
        OptionsTable(&self.queue.collector)
    }

    pub fn collector(&self) -> &Collector {
        &self.queue.collector
    }

    /// The next record, in capture order; `None` at the end of the
    /// capture. A capture that cannot be read on, such as one cut short
    /// mid-packet, ends at the error: it is returned once, then `None`.
    pub fn read(&mut self) -> io::Result<Option<Read>> {
        loop {
            if let Some(read) = self.queue.pop() {
                return Ok(Some(read));
            }
            if self.ended {
                return Ok(None);
            }
            let packet = match self.pcap.next_packet() {
                Some(Ok(packet)) => packet,
                Some(Err(e)) => {
                    self.ended = true;
                    return Err(io_error(e));
                }
                None => {
                    self.ended = true;
                    return Ok(None);
                }
            };
            let Some((exporter, datagram)) = udp_payload(self.link_type, &packet.data) else {
                continue;
            };
            let received = Received {
                exporter,
                time: Some(UNIX_EPOCH + packet.timestamp),
            };
            if let Some(malformed) = self.queue.collect(received, datagram) {
                return Ok(Some(malformed));
            }
        }
    }

    /// The flows alone: options records are kept for
    /// [`PcapReader::options`] but not yielded, and malformed datagrams are
    /// read past.
    pub fn flows(self) -> Flows<Self> {
        Flows(self)
    }
}

/// Every record of the capture, malformed datagrams read past.
impl<R: io::Read> Iterator for PcapReader<R> {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Some(Read::Record(record))) => return Some(Ok(record)),
                Ok(Some(Read::Timeout | Read::Malformed { .. })) => {}
                Ok(None) => return None,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

fn io_error(error: PcapError) -> io::Error {
    match error {
        PcapError::IoError(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    use etherparse::PacketBuilder;

    use super::*;
    use crate::protocol::Protocol;
    use crate::protocol::information_element::iana;
    use crate::protocol::value::Value;

    fn fixture(name: &str) -> String {
        format!(
            "{}/../../tests/fixtures/pcap/{name}_sanity.pcap",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn every_flow_of_the_fixtures_is_read() {
        for (name, family, flows) in [
            ("netflow_v5", Family::Netflow, 10),
            ("netflow_v9", Family::Netflow, 10),
            ("ipfix", Family::Netflow, 10),
            ("sflow_v5", Family::Sflow, 12),
        ] {
            let reader = PcapReader::open(fixture(name), family).unwrap();
            assert_eq!(reader.flows().map(Result::unwrap).count(), flows, "{name}");
        }
    }

    #[test]
    fn options_records_are_read_and_kept() {
        let mut reader = PcapReader::open(fixture("netflow_v9"), Family::Netflow).unwrap();
        let options = reader
            .by_ref()
            .map(Result::unwrap)
            .filter(Record::is_options)
            .count();
        assert!(options > 0);
        assert_eq!(
            reader
                .options()
                .by_element(iana::SAMPLING_INTERVAL)
                .next()
                .unwrap()
                .1
                .first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
    }

    /// Before 2023-11-14T22:13:20Z plus a minute, when the fixtures were
    /// made, and long before any reading of them.
    #[test]
    fn a_datagram_is_received_when_it_was_captured() {
        let reader = PcapReader::open(fixture("netflow_v5"), Family::Netflow).unwrap();
        for record in reader {
            let record = record.unwrap();
            let Some(&Value::DateTimeMilliseconds(millis)) =
                record.first(iana::COLLECTION_TIME_MILLISECONDS)
            else {
                panic!("a collection time");
            };
            assert!((1_700_000_000_000..1_700_000_060_000).contains(&millis));
        }
    }

    /// A pcap of raw IP packets (link type 101), each stamped at second
    /// `1_700_000_000 + its index`.
    fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut pcap = [
            &0xa1b2_c3d4u32.to_le_bytes()[..],
            &2u16.to_le_bytes(),
            &4u16.to_le_bytes(),
            &[0; 8],
            &65_535u32.to_le_bytes(),
            &101u32.to_le_bytes(),
        ]
        .concat();
        for (second, packet) in (1_700_000_000u32..).zip(packets) {
            let length = u32::try_from(packet.len()).unwrap();
            for word in [second, 0, length, length] {
                pcap.extend(word.to_le_bytes());
            }
            pcap.extend(packet);
        }
        pcap
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
            .udp(2055, 9995)
            .write(&mut packet, payload)
            .unwrap();
        packet
    }

    /// A NetFlow v5 header announcing one record, and an empty record.
    fn netflow_v5() -> Vec<u8> {
        [&[0, 5, 0, 1][..], &[0; 20 + 48]].concat()
    }

    #[test]
    fn other_traffic_is_read_past_and_garbage_is_malformed() {
        let mut tcp = Vec::new();
        PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
            .tcp(1, 2, 0, 1024)
            .write(&mut tcp, b"x")
            .unwrap();
        let pcap = capture(&[tcp, udp(&netflow_v5()), udp(&[1, 2, 3])]);
        let mut reader =
            PcapReader::new(Cursor::new(pcap), Collector::of(Family::Netflow)).unwrap();

        let Some(Read::Record(flow)) = reader.read().unwrap() else {
            panic!("expected the v5 flow");
        };
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        assert_eq!(
            flow.first(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS),
            Some(&Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            flow.first(iana::COLLECTION_TIME_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_700_000_001_000))
        );
        let Some(Read::Malformed { exporter, .. }) = reader.read().unwrap() else {
            panic!("expected the garbage to be malformed");
        };
        assert_eq!(exporter, "192.0.2.1:2055".parse().unwrap());
        assert!(reader.read().unwrap().is_none());
    }

    #[test]
    fn a_capture_cut_short_ends_at_its_error() {
        let mut pcap = capture(&[udp(&netflow_v5()), udp(&netflow_v5())]);
        pcap.truncate(pcap.len() - 10);
        let mut reader =
            PcapReader::new(Cursor::new(pcap), Collector::of(Family::Netflow)).unwrap();

        assert!(matches!(reader.read(), Ok(Some(Read::Record(_)))));
        assert!(reader.read().is_err());
        assert!(matches!(reader.read(), Ok(None)));
    }
}
