//! Records from a UDP socket, read with Tokio.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, SystemTime};

use futures_core::Stream;
use socket2::SockRef;
use tokio::io::ReadBuf;
use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::convert::{Received, Record};
use crate::protocol::Family;
use crate::reader::queue::Queue;
use crate::reader::read::{Flows, Read};
use crate::reader::{Collector, OptionsTable};

/// Reads records from a UDP socket, whatever protocol each datagram is in,
/// as a [`Reader`](crate::reader::Reader) does, but awaiting datagrams
/// instead of blocking.
///
/// Its reads are cancel-safe: one dropped before it completes, by a timeout
/// or another `select!` branch, loses no datagram and no record. As a
/// [`Stream`] it yields every record, malformed datagrams read past;
/// [`AsyncReader::flows`] yields the flows alone.
pub struct AsyncReader {
    socket: UdpSocket,
    buf: Vec<u8>,
    queue: Queue,
    read_timeout: Option<Duration>,
}

impl AsyncReader {
    /// Reads `family` from a socket bound to `addr`, with the usual
    /// registry and template timeout; see [`AsyncReader::new`] for others.
    pub async fn bind(addr: impl ToSocketAddrs, family: Family) -> io::Result<Self> {
        Ok(Self::new(
            UdpSocket::bind(addr).await?,
            Collector::of(family),
        ))
    }

    pub fn new(socket: UdpSocket, collector: Collector) -> Self {
        Self {
            socket,
            buf: vec![0; 65_535],
            queue: Queue::new(collector),
            read_timeout: None,
        }
    }

    /// How long a read waits for a datagram before [`Read::Timeout`];
    /// `None` waits forever. Streams wait forever regardless.
    pub fn with_read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Asks the kernel for a receive buffer of `size` bytes, room for
    /// datagrams that arrive faster than they are read; the kernel may
    /// grant another size, which [`AsyncReader::recv_buffer_size`] tells.
    pub fn with_recv_buffer_size(self, size: usize) -> io::Result<Self> {
        SockRef::from(&self.socket).set_recv_buffer_size(size)?;
        Ok(self)
    }

    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        SockRef::from(&self.socket).recv_buffer_size()
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

    /// The next record, in the order the exporters sent them, or a datagram
    /// that could not be parsed. Datagrams that carry no records, such as
    /// template-only ones, are read past.
    pub async fn read(&mut self) -> io::Result<Read> {
        loop {
            if let Some(read) = self.queue.pop() {
                return Ok(read);
            }
            let receive = self.socket.recv_from(&mut self.buf);
            let (len, from) = match self.read_timeout {
                Some(timeout) => match tokio::time::timeout(timeout, receive).await {
                    Ok(received) => received?,
                    Err(_) => return Ok(Read::Timeout),
                },
                None => receive.await?,
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

    /// The next flow: options records are kept for
    /// [`AsyncReader::options`] but not returned, and timeouts and
    /// malformed datagrams are read past.
    pub async fn next_flow(&mut self) -> io::Result<Record> {
        loop {
            if let Read::Record(record) = self.read().await?
                && !record.is_options()
            {
                return Ok(record);
            }
        }
    }

    /// The flows alone, as a [`Stream`]: options records are kept for
    /// [`AsyncReader::options`] but not yielded, and malformed datagrams are
    /// read past.
    pub fn flows(self) -> Flows<Self> {
        Flows(self)
    }
}

/// Every record, malformed datagrams read past.
impl Stream for AsyncReader {
    type Item = io::Result<Record>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(Read::Record(record)) = this.queue.pop() {
                return Poll::Ready(Some(Ok(record)));
            }
            let mut buf = ReadBuf::new(&mut this.buf);
            let from = match ready!(this.socket.poll_recv_from(cx, &mut buf)) {
                Ok(from) => from,
                Err(e) => return Poll::Ready(Some(Err(e))),
            };
            let received = Received {
                exporter: from,
                time: Some(SystemTime::now()),
            };
            this.queue.collect(received, buf.filled());
        }
    }
}

impl Stream for Flows<AsyncReader> {
    type Item = io::Result<Record>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.0).poll_next(cx)) {
                Some(Ok(record)) if record.is_options() => {}
                item => return Poll::Ready(item),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket as StdUdpSocket;

    use super::*;
    use crate::protocol::Protocol;
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

    /// A NetFlow v5 header announcing one record, and an empty record.
    fn netflow_v5() -> Vec<u8> {
        [words(&[5, 1]), vec![0; 20 + 48]].concat()
    }

    /// Options scoped by observationDomainId(149) with samplingInterval(34):
    /// the options template, then a record of it.
    fn sampling_options() -> [Vec<u8>; 2] {
        let template = ipfix(&[set(
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
        let record = ipfix(&[set(
            257,
            &[7u32.to_be_bytes(), 100u32.to_be_bytes()].concat(),
        )]);
        [template, record]
    }

    async fn reader() -> (AsyncReader, StdUdpSocket, SocketAddr) {
        let reader = AsyncReader::bind("127.0.0.1:0", Family::Netflow)
            .await
            .unwrap();
        let sender = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = reader.local_addr().unwrap();
        (reader, sender, addr)
    }

    #[tokio::test]
    async fn records_and_malformed_datagrams_are_read_in_order() {
        let (mut reader, sender, addr) = reader().await;
        for datagram in [&netflow_v5(), &[1, 2, 3][..]] {
            sender.send_to(datagram, addr).unwrap();
        }

        let Read::Record(flow) = reader.read().await.unwrap() else {
            panic!("expected the v5 flow");
        };
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        let Read::Malformed { exporter, .. } = reader.read().await.unwrap() else {
            panic!("expected the garbage to be malformed");
        };
        assert_eq!(exporter, sender.local_addr().unwrap());
    }

    #[tokio::test]
    async fn the_next_flow_leaves_options_records_out_and_keeps_them() {
        let (mut reader, sender, addr) = reader().await;
        let [template, options] = sampling_options();
        for datagram in [&template, &options, &[1, 2, 3][..], &netflow_v5()] {
            sender.send_to(datagram, addr).unwrap();
        }

        let flow = reader.next_flow().await.unwrap();
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        let (_, options) = reader
            .options()
            .by_element(iana::SAMPLING_INTERVAL)
            .next()
            .unwrap();
        assert_eq!(
            options.first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
    }

    async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
        std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
    }

    #[tokio::test]
    async fn a_read_times_out_and_a_later_datagram_is_still_read() {
        let (reader, sender, addr) = reader().await;
        let mut reader = reader.with_read_timeout(Some(Duration::from_millis(20)));
        assert!(matches!(reader.read().await.unwrap(), Read::Timeout));

        sender.send_to(&netflow_v5(), addr).unwrap();
        assert!(matches!(reader.read().await.unwrap(), Read::Record(_)));
    }

    #[tokio::test]
    async fn as_a_stream_it_yields_every_record_and_its_flows_alone() {
        let (mut reader, sender, addr) = reader().await;
        let [template, options] = sampling_options();
        for datagram in [&template, &options, &[1, 2, 3][..], &netflow_v5()] {
            sender.send_to(datagram, addr).unwrap();
        }
        let options = next(&mut reader).await.unwrap().unwrap();
        assert!(options.is_options());
        let flow = next(&mut reader).await.unwrap().unwrap();
        assert_eq!(flow.protocol, Protocol::NetflowV5);

        let mut flows = reader.flows();
        for datagram in [&template, &sampling_options()[1], &netflow_v5()] {
            sender.send_to(datagram, addr).unwrap();
        }
        let flow = next(&mut flows).await.unwrap().unwrap();
        assert_eq!(flow.protocol, Protocol::NetflowV5);
        assert_eq!(flows.reader().options().iter().count(), 1);
    }
}
