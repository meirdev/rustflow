use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use log::{debug, info};
use rustflow_core::ipfix::{
    DataSet, HEADER_LENGTH, Header, OptionsTemplate, Packet, SET_HEADER_LENGTH, Set, Template,
    VARIABLE_LENGTH, VERSION, encode_packet,
};
use rustflow_core::value::{Value, natural_length};

use crate::ExportArgs;
use crate::flow::Flow;
use crate::ipfix::data::{OptionsData, PacketData};
use crate::ipfix::template::{create_options_template, create_templates, data_template};
use crate::meter::Records;

/// Keeps a message within one Ethernet MTU, with
/// room for IPv6 and UDP headers.
const MAX_MESSAGE_SIZE: usize = 1400;
/// Less the set's header, and the up to 3 octets of padding the encoder may
/// add to end it on a 4-octet boundary.
const MAX_SET_BODY: usize =
    MAX_MESSAGE_SIZE - HEADER_LENGTH as usize - SET_HEADER_LENGTH as usize - 3;

pub struct Exporter {
    socket: UdpSocket,
    /// Resolved once at startup.
    collector_addr: SocketAddr,
    args: ExportArgs,
    sequence_number: AtomicU32,
    last_template_send: Instant,
    options_template: Arc<OptionsTemplate>,
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

        Ok(Self {
            socket,
            collector_addr,
            options_template: create_options_template(args.sampling()),
            args,
            sequence_number: AtomicU32::new(0),
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

    /// Sends one message with `sets`; returns its size.
    fn send_sets(&mut self, sets: Vec<Set>) -> Result<usize> {
        let packet = Packet {
            header: Header {
                version: VERSION,
                length: 0, // Will be calculated during encoding
                export_time: Utc::now().timestamp() as u32,
                sequence_number: self.sequence_number.load(Ordering::SeqCst),
                observation_domain_id: self.args.observation_domain_id,
            },
            sets,
        };

        let mut encoded = Vec::new();
        encode_packet(&mut encoded, &packet).context("Failed to encode an IPFIX message")?;
        self.socket.send_to(&encoded, self.collector_addr)?;

        Ok(encoded.len())
    }

    /// Sends one message with one set of data records of `template`.
    fn send_data(&mut self, template: Arc<Template>, records: Vec<Vec<Value>>) -> Result<()> {
        let count = records.len() as u32;
        let size = self.send_sets(vec![Set::Data(DataSet { template, records })])?;
        self.sequence_number.fetch_add(count, Ordering::SeqCst);

        debug!("Sent packet with {} records ({} bytes)", count, size);

        Ok(())
    }

    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        self.send_sets(vec![
            Set::Templates(create_templates(self.args.mode)),
            Set::OptionsTemplates(vec![Arc::clone(&self.options_template)]),
        ])?;

        self.last_template_send = Instant::now();
        debug!("Templates sent successfully");

        Ok(())
    }

    pub fn send_options_data(&mut self) -> Result<()> {
        debug!("Sending options data");

        // Options Data Records count toward the sequence number (RFC 7011
        // section 3.1), like any other Data Record.
        let options_data = OptionsData::new(self.args.observation_domain_id, self.args.sampling());
        let records = vec![options_data.to_record()];
        let count = records.len() as u32;
        self.send_sets(vec![Set::OptionsData(DataSet {
            template: Arc::clone(&self.options_template),
            records,
        })])?;
        self.sequence_number.fetch_add(count, Ordering::SeqCst);

        debug!("Options data sent successfully");

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
        let (ipv4, ipv6): (Vec<_>, Vec<_>) = flows
            .iter()
            .map(Flow::to_flow_data)
            .partition(|data| data.source_ip.is_ipv4());

        self.send_records(
            ipv4.iter()
                .chain(&ipv6)
                .map(|data| (data.template_id(), data.to_record())),
        )
    }

    fn send_packets(&mut self, packets: Vec<PacketData>) -> Result<()> {
        self.send_records(
            packets
                .iter()
                .map(|packet| (packet.template_id(), packet.to_record())),
        )
    }

    /// Sends each record with its template ID, filling every message by
    /// bytes up to [`MAX_MESSAGE_SIZE`]; a new template starts a new message.
    ///
    /// Every message is tried, so a failed send costs only its own records;
    /// the first error is returned.
    fn send_records(&mut self, records: impl IntoIterator<Item = (u16, Vec<Value>)>) -> Result<()> {
        let mut result = Ok(());
        let mut pending = Vec::new();
        let mut current: Option<Arc<Template>> = None;
        let mut size = 0;

        for (id, record) in records {
            let template = match current.take() {
                Some(template) if template.template_id == id => template,
                previous => {
                    if let Some(previous) = previous {
                        result = result.and(self.send_data(previous, std::mem::take(&mut pending)));
                    }
                    size = 0;
                    data_template(id).expect("every record has one of the exporter's templates")
                }
            };
            let len = record_length(&template, &record);
            if !pending.is_empty() && size + len > MAX_SET_BODY {
                result =
                    result.and(self.send_data(Arc::clone(&template), std::mem::take(&mut pending)));
                size = 0;
            }
            size += len;
            pending.push(record);
            current = Some(template);
        }
        if let Some(template) = current {
            result = result.and(self.send_data(template, pending));
        }

        result
    }
}

/// The octets `record` takes in a data set of `template`.
fn record_length(template: &Template, record: &[Value]) -> usize {
    template
        .fields
        .iter()
        .zip(record)
        .map(|(field, value)| match field.field_length {
            VARIABLE_LENGTH => {
                let length = match value {
                    Value::OctetArray(octets) => octets.len(),
                    Value::String(text) => text.len(),
                    value => natural_length(value).unwrap_or(0),
                };
                // A one-octet length prefix, or 255 and two octets.
                length + if length < 255 { 1 } else { 3 }
            }
            length => usize::from(length),
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    use clap::Parser;
    use rustflow_core::information_element::Registry;
    use rustflow_core::ipfix;
    use rustflow_core::timed_map::BoundedTimedMap;

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

    fn parser() -> ipfix::Parser {
        let ttl = Duration::from_mins(10);
        ipfix::Parser::new(
            Registry::iana(),
            BoundedTimedMap::new(16, ttl),
            BoundedTimedMap::new(16, ttl),
        )
    }

    /// The data records of a message, options records left out.
    fn data_records(message: &ipfix::Packet) -> usize {
        message
            .sets
            .iter()
            .filter_map(|set| set.as_data())
            .map(|set| set.records.len())
            .sum()
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
            exporter.send_options_data().unwrap();
            exporter.send(Records::Flows(vec![flow()])).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn options_and_data_records_advance_the_sequence_number() {
        let receiver = receiver();
        let mut exporter = exporter(&receiver, &["--mode", "packet"]);

        exporter.send_templates().unwrap();
        exporter.send_options_data().unwrap();
        exporter
            .send(Records::Packets(vec![packet(16); 3]))
            .unwrap();
        exporter.send_options_data().unwrap();
        exporter.send(Records::Flows(vec![flow()])).unwrap();

        let mut parser = parser();
        let sequence: Vec<u32> = datagrams(&receiver)
            .iter()
            .map(|message| parser.parse(message).unwrap().header.sequence_number)
            .collect();
        // Templates do not count; one options record, three packets, one
        // options record, one flow.
        assert_eq!(sequence, [0, 0, 1, 4, 5]);
        assert_eq!(exporter.sequence_number.load(Ordering::SeqCst), 6);
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
