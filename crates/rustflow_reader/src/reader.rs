use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime};

use rustflow_convert::{Received, Record};
use rustflow_protocol::ParseError;

use crate::collector::Collector;
use crate::options::OptionsTable;

/// Reads records from a UDP socket, whatever protocol each datagram is in.
pub struct Reader {
    socket: UdpSocket,
    buf: Vec<u8>,
    collector: Collector,
    pending: VecDeque<Record>,
}

/// What one read turned up.
#[derive(Debug)]
pub enum Read {
    /// A flow, or an options record with its scope.
    Record(Record),
    /// No datagram before the read timeout.
    Timeout,
    /// A datagram that could not be parsed.
    Malformed {
        exporter: SocketAddr,
        error: ParseError,
    },
}

impl Reader {
    pub fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self::new(UdpSocket::bind(addr)?, Collector::default()))
    }

    pub fn new(socket: UdpSocket, collector: Collector) -> Self {
        Self {
            socket,
            buf: vec![0; 65_535],
            collector,
            pending: VecDeque::new(),
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
        OptionsTable(&self.collector)
    }

    /// The next record, in the order the exporters sent them. Datagrams
    /// that carry no records, such as template-only ones, are read past.
    pub fn read(&mut self) -> io::Result<Read> {
        loop {
            if let Some(record) = self.pending.pop_front() {
                return Ok(Read::Record(record));
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
            if let Err(error) =
                self.collector
                    .collect(received, &self.buf[..len], &mut self.pending)
            {
                return Ok(Read::Malformed {
                    exporter: from,
                    error,
                });
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

/// The flows of a reader; see [`Reader::flows`].
pub struct Flows(Reader);

impl Flows {
    pub fn reader(&self) -> &Reader {
        &self.0
    }
}

impl Iterator for Flows {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .find(|record| !record.as_ref().is_ok_and(Record::is_options))
    }
}

#[cfg(test)]
mod tests {
    use rustflow_convert::Scope;
    use rustflow_protocol::information_element::iana;
    use rustflow_protocol::value::Value;

    use super::*;

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

    fn reader() -> (Reader, UdpSocket, SocketAddr) {
        let reader = Reader::bind("127.0.0.1:0")
            .unwrap()
            .with_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = reader.local_addr().unwrap();
        (reader, sender, addr)
    }

    #[test]
    fn records_of_every_protocol_are_read_in_order_and_options_are_kept() {
        let (mut reader, sender, addr) = reader();
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
        // An sFlow datagram from agent 192.0.2.1 with one flow sample of no
        // records: version, address type and address, sub-agent, sequence,
        // uptime, sample count; then the sample's format, length and body.
        let sflow: Vec<u8> = [
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
        ]
        .iter()
        .flat_map(|word: &u32| word.to_be_bytes())
        .collect();
        for datagram in [&templates, &options, &data, &v5, &sflow, &[1, 2, 3][..]] {
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
        let Read::Record(flow) = reader.read().unwrap() else {
            panic!("expected the sFlow flow");
        };
        assert_eq!(flow.protocol, Protocol::SflowV5);
        assert_eq!(
            flow.first(iana::SAMPLING_POPULATION),
            Some(&Value::Unsigned32(1000))
        );
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

    #[test]
    fn flows_leave_options_records_out() {
        let (reader, sender, addr) = reader();
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

    use rustflow_convert::Protocol;
}
