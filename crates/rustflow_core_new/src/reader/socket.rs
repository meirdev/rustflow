use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime};

use crate::convert::{Received, Record};
use crate::protocol::Family;
use crate::reader::collector::Collector;
use crate::reader::options::OptionsTable;
use crate::reader::queue::Queue;
use crate::reader::read::{Flows, Read};

/// Reads records from a UDP socket, whatever protocol each datagram is in.
pub struct Reader {
    socket: UdpSocket,
    buf: Vec<u8>,
    queue: Queue,
}

impl Reader {
    /// Reads `family` from a socket bound to `addr`, with the usual
    /// registry and template timeout; see [`Reader::new`] for others.
    pub fn bind(addr: impl ToSocketAddrs, family: Family) -> io::Result<Self> {
        Ok(Self::new(UdpSocket::bind(addr)?, Collector::of(family)))
    }

    pub fn new(socket: UdpSocket, collector: Collector) -> Self {
        Self {
            socket,
            buf: vec![0; 65_535],
            queue: Queue::new(collector),
        }
    }

    /// How long a read waits for a datagram before [`Read::Timeout`];
    /// `None` waits forever.
    pub fn with_read_timeout(self, timeout: Option<Duration>) -> io::Result<Self> {
        self.socket.set_read_timeout(timeout)?;
        Ok(self)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The latest options records read, by exporter, domain and scope.
    pub fn options(&self) -> OptionsTable<'_> {
        OptionsTable(&self.queue.collector)
    }

    pub fn collector(&self) -> &Collector {
        &self.queue.collector
    }

    /// The next record, in the order the exporters sent them. Datagrams
    /// that carry no records, such as template-only ones, are read past.
    pub fn read(&mut self) -> io::Result<Read> {
        loop {
            if let Some(read) = self.queue.pop() {
                return Ok(read);
            }
            let (len, from) = match self.socket.recv_from(&mut self.buf) {
                Ok(received) => received,
                Err(e) if is_retryable(&e) => return Ok(Read::Timeout),
                Err(e) => return Err(e),
            };
            let received = Received {
                exporter: from,
                time: Some(SystemTime::now()),
            };
            if let Some(malformed) = self.queue.collect(received, &self.buf[..len]) {
                return Ok(malformed);
            }
        }
    }

    /// The flows alone: options records are kept for [`Reader::options`]
    /// but not yielded, and timeouts and malformed datagrams are read past.
    pub fn flows(self) -> Flows {
        Flows(self)
    }
}

/// A read timeout, a non-blocking miss, or a syscall interrupted by a
/// signal: no datagram this time, nothing wrong with the socket.
fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Every record a reader reads, timeouts and malformed datagrams read
/// past.
impl Iterator for Reader {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read() {
                Ok(Read::Record(record)) => return Some(Ok(record)),
                Ok(Read::Timeout | Read::Malformed { .. }) => {}
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::Scope;
    use crate::protocol::information_element::iana;
    use crate::protocol::value::Value;

    fn words(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn ipfix(sets: &[Vec<u8>]) -> Vec<u8> {
        let body = sets.concat();
        let length = u16::try_from(16 + body.len()).unwrap();
        [
            words(&[10, length]),
            1_700_000_000u32.to_be_bytes().to_vec(),
            42u32.to_be_bytes().to_vec(),
            7u32.to_be_bytes().to_vec(),
            body,
        ]
        .concat()
    }

    fn set(id: u16, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(4 + body.len()).unwrap();
        [&words(&[id, length])[..], body].concat()
    }

    fn reader(family: Family) -> (Reader, UdpSocket, SocketAddr) {
        let reader = Reader::bind("127.0.0.1:0", family)
            .unwrap()
            .with_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = reader.local_addr().unwrap();
        (reader, sender, addr)
    }

    #[test]
    fn records_of_every_protocol_are_read_in_order_and_options_are_kept() {
        let (mut reader, sender, addr) = reader(Family::Netflow);
        // Template 256: octetDeltaCount(1); options template 257 scoped by
        // observationDomainId(149) with samplingInterval(34).
        let templates = ipfix(&[
            set(2, &words(&[256, 1, iana::OCTET_DELTA_COUNT.id, 4])),
            set(
                3,
                &words(&[
                    257,
                    2,
                    1,
                    iana::OBSERVATION_DOMAIN_ID.id,
                    4,
                    iana::SAMPLING_INTERVAL.id,
                    4,
                ]),
            ),
        ]);
        let options = ipfix(&[set(
            257,
            &[7u32.to_be_bytes(), 100u32.to_be_bytes()].concat(),
        )]);
        let data = ipfix(&[set(256, &5u32.to_be_bytes())]);
        // A NetFlow v5 header announcing one record, and an empty record.
        let v5 = [words(&[5, 1]), vec![0; 20 + 48]].concat();
        for datagram in [&templates, &options, &data, &v5, &sflow(), &[1, 2, 3][..]] {
            sender.send_to(datagram, addr).unwrap();
        }

        let Read::Record(options) = reader.read().unwrap() else {
            panic!("expected the options record");
        };
        assert_eq!(
            options.scope,
            [(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(7)
            )]
        );
        let Read::Record(flow) = reader.read().unwrap() else {
            panic!("expected the IPFIX flow");
        };
        assert_eq!(flow.protocol, Protocol::Ipfix);
        assert_eq!(
            flow.first(iana::SAMPLING_PACKET_SPACE),
            Some(&Value::Unsigned32(99))
        );
        let Read::Record(flow) = reader.read().unwrap() else {
            panic!("expected the v5 flow");
        };
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        // sFlow is not NetFlow's business, nor is garbage.
        assert!(matches!(reader.read().unwrap(), Read::Malformed { .. }));
        assert!(matches!(reader.read().unwrap(), Read::Malformed { .. }));
        assert!(matches!(reader.read().unwrap(), Read::Timeout));

        let scope = [(
            Scope::Element(iana::OBSERVATION_DOMAIN_ID),
            Value::Unsigned32(7),
        )];
        let exporter = sender.local_addr().unwrap();
        let kept: Vec<_> = reader.options().get(exporter, 7, &scope).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
        assert_eq!(
            reader.options().by_element(iana::SAMPLING_INTERVAL).count(),
            1
        );
    }

    /// An sFlow datagram from agent 192.0.2.1 with one flow sample of no
    /// records: version, address type and address, sub-agent, sequence,
    /// uptime, sample count; then the sample's format, length and body.
    fn sflow() -> Vec<u8> {
        let words: [u32; 17] = [
            5,
            1,
            0xc000_0201,
            0,
            1,
            0,
            1,
            1,
            32,
            1,
            1,
            1000,
            0,
            0,
            0,
            0,
            0,
        ];
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    #[test]
    fn an_sflow_reader_reads_sflow_alone() {
        let (mut reader, sender, addr) = reader(Family::Sflow);
        let v5 = [words(&[5, 1]), vec![0; 20 + 48]].concat();
        for datagram in [&sflow(), &v5] {
            sender.send_to(datagram, addr).unwrap();
        }
        let Read::Record(flow) = reader.read().unwrap() else {
            panic!("expected the sFlow flow");
        };
        assert_eq!(flow.protocol, Protocol::SflowV5);
        assert_eq!(
            flow.first(iana::SAMPLING_POPULATION),
            Some(&Value::Unsigned32(1000))
        );
        assert!(matches!(reader.read().unwrap(), Read::Malformed { .. }));
    }

    #[test]
    fn flows_leave_options_records_out() {
        let (reader, sender, addr) = reader(Family::Netflow);
        let templates = ipfix(&[set(
            3,
            &words(&[
                257,
                2,
                1,
                iana::OBSERVATION_DOMAIN_ID.id,
                4,
                iana::SAMPLING_INTERVAL.id,
                4,
            ]),
        )]);
        let options = ipfix(&[set(
            257,
            &[7u32.to_be_bytes(), 100u32.to_be_bytes()].concat(),
        )]);
        let v5 = [words(&[5, 1]), vec![0; 20 + 48]].concat();
        for datagram in [&templates, &options, &v5] {
            sender.send_to(datagram, addr).unwrap();
        }
        let mut flows = reader.flows();
        let flow = flows.next().unwrap().unwrap();
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        assert_eq!(flows.reader().options().iter().count(), 1);
    }

    use crate::convert::Protocol;
}
