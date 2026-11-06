use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use log::{debug, info};
use rustflow_core::convert::Record;
use rustflow_core::export;
use rustflow_core::protocol::ipfix;

use crate::ExportArgs;
use crate::flow::Flow;
use crate::meter::{Mode, Records};
use crate::records::{PacketData, Shapes, wire_size};

/// Keeps a message within one Ethernet MTU, with room for IPv6 and UDP
/// headers.
const MAX_MESSAGE_SIZE: usize = 1400;
/// Message header and set header.
const HEADERS: usize = 16 + 4;
const MAX_SET_BODY: usize = MAX_MESSAGE_SIZE - HEADERS;

pub struct Exporter {
    socket: UdpSocket,
    /// Resolved once at startup.
    collector_addr: SocketAddr,
    args: ExportArgs,
    ipfix: export::ipfix::Exporter,
    shapes: Shapes,
    buf: Vec<u8>,
    last_template_send: Instant,
}

impl Exporter {
    pub fn new(args: ExportArgs) -> Result<Self> {
        let collector_addr = args.collector_addr()?;
        info!("Exporting to collector at {}", collector_addr);

        // The socket stays unconnected: a connected one fails its next send
        // after any ICMP port unreachable, as while the collector is down. It
        // is not bound to an address either, so each send takes the source
        // address the route picks then, and a link-local collector keeps its
        // scope.
        let socket = UdpSocket::bind(if collector_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?;

        // Every template is made now, so that they all go out together
        // ahead of the records rather than each with its first record.
        let shapes = Shapes::default();
        let mut ipfix = export::ipfix::Exporter::new(args.observation_domain_id);
        let [ipv4, ipv6, frame, ip] = shapes.samples();
        let samples = match args.mode {
            Mode::Flow => [ipv4, ipv6],
            Mode::Packet => [frame, ip],
        };
        for sample in samples
            .iter()
            .chain(&[shapes.options(args.observation_domain_id, args.sampling())])
        {
            ipfix.declare(sample)?;
        }

        Ok(Self {
            socket,
            collector_addr,
            args,
            ipfix,
            shapes,
            buf: Vec::new(),
            last_template_send: Instant::now(),
        })
    }

    pub fn collector_addr(&self) -> SocketAddr {
        self.collector_addr
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn should_send_template(&self) -> bool {
        let elapsed = Instant::now().duration_since(self.last_template_send);
        elapsed >= Duration::from_secs(self.args.template_refresh_rate)
    }

    /// Sends one message of `records`, with the templates if they are due;
    /// returns its size.
    fn send_message(&mut self, records: &[Record]) -> Result<usize> {
        let packet = self.ipfix.export(records, SystemTime::now())?;
        self.buf.clear();
        ipfix::write(&packet, &mut self.buf)?;
        self.socket.send_to(&self.buf, self.collector_addr)?;
        Ok(self.buf.len())
    }

    /// Sends every template with the options data record that says how the
    /// observation domain samples. Options data records count toward the
    /// sequence number (RFC 7011 section 3.1), like any other data record.
    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        self.ipfix.resend_templates();
        let options = self
            .shapes
            .options(self.args.observation_domain_id, self.args.sampling());
        self.send_message(&[options])?;

        self.last_template_send = Instant::now();
        debug!("Templates sent successfully");

        Ok(())
    }

    pub fn send(&mut self, records: Records) -> Result<()> {
        match records {
            Records::Flows(flows) => self.send_flows(flows),
            Records::Packets(packets) => self.send_packets(packets),
        }
    }

    fn send_flows(&mut self, flows: Vec<Flow>) -> Result<()> {
        if flows.is_empty() {
            return Ok(());
        }

        info!("Exporting {} flows", flows.len());

        // A set holds records of one template, so IPv4 and IPv6 flows are
        // sent apart rather than interleaved.
        let (ipv4, ipv6): (Vec<_>, Vec<_>) =
            flows.iter().partition(|flow| flow.key.source_ip.is_ipv4());
        let records: Vec<_> = ipv4
            .iter()
            .chain(&ipv6)
            .map(|flow| self.shapes.flow(flow))
            .collect();
        self.send_records(records)
    }

    fn send_packets(&mut self, packets: Vec<PacketData>) -> Result<()> {
        let records: Vec<_> = packets
            .iter()
            .map(|packet| self.shapes.packet(packet))
            .collect();
        self.send_records(records)
    }

    /// Sends the records, filling every message by bytes up to
    /// [`MAX_MESSAGE_SIZE`]; a new shape starts a new message.
    ///
    /// Every message is tried, so a failed send costs only its own records;
    /// the first error is returned.
    fn send_records(&mut self, records: Vec<Record>) -> Result<()> {
        let mut result = Ok(());
        let mut pending: Vec<Record> = Vec::new();
        let mut size = 0;

        for record in records {
            let len = wire_size(&record);
            let new_shape = pending
                .last()
                .is_some_and(|last| !std::sync::Arc::ptr_eq(&last.elements, &record.elements));
            if !pending.is_empty() && (size + len > MAX_SET_BODY || new_shape) {
                result = result.and(self.send_pending(&mut pending));
                size = 0;
            }
            size += len;
            pending.push(record);
        }
        if !pending.is_empty() {
            result = result.and(self.send_pending(&mut pending));
        }

        result
    }

    fn send_pending(&mut self, pending: &mut Vec<Record>) -> Result<()> {
        let count = pending.len();
        let size = self.send_message(pending)?;
        pending.clear();
        debug!("Sent packet with {} records ({} bytes)", count, size);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    use clap::Parser;
    use rustflow_core::protocol::information_element::Registry;
    use rustflow_core::protocol::ipfix::{Packet, Parser as IpfixParser, Set};

    use super::*;
    use crate::capture::Link;
    use crate::flow::{FlowKey, Seen};

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: ExportArgs,
    }

    /// An exporter sending to `receiver`.
    fn exporter(receiver: &UdpSocket, flags: &[&str]) -> Exporter {
        let port = receiver.local_addr().unwrap().port().to_string();
        let cli = Cli::parse_from([&["export", "-H", "127.0.0.1", "-p", &port], flags].concat());
        Exporter::new(cli.args).unwrap()
    }

    fn receiver() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        socket
    }

    /// Every datagram received so far.
    fn datagrams(receiver: &UdpSocket) -> Vec<Vec<u8>> {
        let mut buf = vec![0; 65535];
        let mut received = Vec::new();
        while let Ok(len) = receiver.recv(&mut buf) {
            received.push(buf[..len].to_vec());
        }
        received
    }

    fn parser() -> IpfixParser {
        IpfixParser::new(Registry::iana(), Duration::from_secs(600))
    }

    /// The data records of a message, options records left out.
    fn data_records(message: &Packet) -> usize {
        message
            .sets
            .iter()
            .map(|set| match set {
                Set::Data(data) => data.records.len(),
                _ => 0,
            })
            .sum()
    }

    fn packet(section_len: usize) -> PacketData {
        PacketData {
            link: Link::Ethernet,
            length: 1500,
            section: vec![0xab; section_len],
        }
    }

    fn flow() -> Flow {
        let mut flow = Flow::new(
            FlowKey {
                source_ip: "10.0.0.1".parse().unwrap(),
                destination_ip: "10.0.0.2".parse().unwrap(),
                protocol: 6,
                source_port: 1,
                destination_port: 2,
            },
            Seen::now(),
        );
        flow.update(100, 0, Seen::now());
        flow
    }

    #[test]
    fn a_collector_that_is_not_listening_does_not_stop_the_exporter() {
        // Nothing listens on the port, so every datagram draws an ICMP port
        // unreachable.
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cli = Cli::parse_from(["export", "-H", "127.0.0.1", "-p", &port.to_string()]);
        let mut exporter = Exporter::new(cli.args).unwrap();

        for _ in 0..3 {
            exporter.send_templates().unwrap();
            exporter.send(Records::Flows(vec![flow()])).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn templates_go_first_and_records_advance_the_sequence_number() {
        let receiver = receiver();
        let mut exporter = exporter(&receiver, &["--mode", "packet"]);

        exporter.send_templates().unwrap();
        exporter
            .send(Records::Packets(vec![packet(16); 3]))
            .unwrap();
        exporter.send_templates().unwrap();
        exporter.send(Records::Flows(vec![flow()])).unwrap();

        let mut parser = parser();
        let messages: Vec<_> = datagrams(&receiver)
            .iter()
            .map(|message| parser.parse(message).unwrap())
            .collect();
        // Templates do not count; one options record, three packets, one
        // options record, one flow.
        let sequence: Vec<u32> = messages
            .iter()
            .map(|message| message.header.sequence_number)
            .collect();
        assert_eq!(sequence, [0, 1, 4, 5]);
        assert!(messages[0].has_templates(), "templates with the options");
        assert!(!messages[1].has_templates());
        assert!(messages[2].has_templates(), "sent again on request");
        // In packet mode no flow template was declared, so the flow's own
        // message brings its template, ahead of the record.
        assert!(messages[3].has_templates() && !messages[3].has_undecoded());
        assert_eq!(data_records(&messages[3]), 1);
    }

    #[test]
    fn flow_messages_are_filled_by_bytes_within_the_mtu() {
        let receiver = receiver();
        let mut exporter = exporter(&receiver, &[]);
        exporter.send_templates().unwrap();

        let ipv6 = |port| {
            let mut flow = Flow::new(
                FlowKey {
                    source_ip: "2001:db8::1".parse().unwrap(),
                    destination_ip: "2001:db8::2".parse().unwrap(),
                    protocol: 17,
                    source_port: port,
                    destination_port: 53,
                },
                Seen::now(),
            );
            flow.update(100, 0, Seen::now());
            flow
        };
        let flows = (0..100).map(|_| flow()).chain((0..50).map(ipv6)).collect();
        exporter.send(Records::Flows(flows)).unwrap();

        let messages = datagrams(&receiver);
        let mut parser = parser();
        let mut records = 0;
        for message in &messages {
            records += data_records(&parser.parse(message).unwrap());
            assert!(message.len() <= MAX_MESSAGE_SIZE, "{}", message.len());
        }
        assert_eq!(records, 150);
        // 49-byte IPv4 records: 28 per message; 73-byte IPv6 records: 18.
        assert_eq!(messages.len(), 1 + 4 + 3);
    }

    #[test]
    fn packet_messages_are_filled_by_bytes_within_the_mtu() {
        let receiver = receiver();
        let mut exporter = exporter(&receiver, &["--mode", "packet"]);
        exporter.send_templates().unwrap();

        exporter
            .send(Records::Packets(vec![packet(128); 20]))
            .unwrap();
        exporter
            .send(Records::Packets(vec![packet(1024); 5]))
            .unwrap();

        let messages = datagrams(&receiver);
        let mut parser = parser();
        let mut records = 0;
        for message in &messages {
            records += data_records(&parser.parse(message).unwrap());
            assert!(message.len() <= MAX_MESSAGE_SIZE);
        }
        assert_eq!(records, 25);
        // 131-byte records: ten per message; 1029-byte records: one each.
        assert_eq!(messages.len(), 1 + 2 + 5);
    }
}
