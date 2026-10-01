use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use log::{debug, info};
use rustflow_core::common::encoder::Encode;
use rustflow_core::ipfix::parser::{
    Header, IPFIX_HEADER_SIZE, IPFIX_OPTIONS_TEMPLATE_SET_ID, IPFIX_TEMPLATE_SET_ID, IPFIX_VERSION,
    IpfixPacket, Record, SET_HEADER_SIZE, Set,
};

use crate::ExportArgs;
use crate::flow::Flow;
use crate::ipfix::data::{OptionsData, PacketData};
use crate::ipfix::template::{OPTIONS_TEMPLATE_ID, create_options_template, create_templates};
use crate::meter::Records;

// Maximum data records per set
const MAX_RECORDS_PER_SET: usize = 30;

/// Keeps a message of packet records within one Ethernet MTU.
const MAX_MESSAGE_SIZE: usize = 1400;
const MAX_SET_BODY: usize = MAX_MESSAGE_SIZE - IPFIX_HEADER_SIZE - SET_HEADER_SIZE;

pub struct Exporter {
    socket: UdpSocket,
    /// Resolved once at startup.
    collector_addr: SocketAddr,
    args: ExportArgs,
    sequence_number: AtomicU32,
    last_template_send: Instant,
}

impl Exporter {
    pub fn new(args: ExportArgs) -> Result<Self> {
        let collector_addr = args.collector_addr()?;
        info!("Connecting to collector at {}", collector_addr);

        let socket = UdpSocket::bind(if collector_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?;
        socket.connect(collector_addr)?;

        Ok(Self {
            socket,
            collector_addr,
            args,
            sequence_number: AtomicU32::new(0),
            last_template_send: Instant::now() - Duration::from_secs(9999), // Force initial send
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
        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0, // Will be calculated during encoding
                export_time: Utc::now(),
                sequence_number: self.sequence_number.load(Ordering::SeqCst),
                observation_domain_id: self.args.observation_domain_id,
            },
            sets,
        };

        let mut encoded = Vec::new();
        packet.encode(&mut encoded);
        self.socket.send(&encoded)?;

        Ok(encoded.len())
    }

    /// Sends one message with one set of data records of `template_id`.
    fn send_data(&mut self, template_id: u16, records: Vec<Record>) -> Result<()> {
        let count = records.len() as u32;
        let size = self.send_sets(vec![Set {
            id: template_id,
            length: 0,
            records,
        }])?;
        self.sequence_number.fetch_add(count, Ordering::SeqCst);

        debug!("Sent packet with {} records ({} bytes)", count, size);

        Ok(())
    }

    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        self.send_sets(vec![
            Set {
                id: IPFIX_TEMPLATE_SET_ID,
                length: 0,
                records: create_templates(self.args.mode)
                    .into_iter()
                    .map(Record::Template)
                    .collect(),
            },
            Set {
                id: IPFIX_OPTIONS_TEMPLATE_SET_ID,
                length: 0,
                records: vec![Record::OptionsTemplate(create_options_template(
                    self.args.sampling(),
                ))],
            },
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
        self.send_data(
            OPTIONS_TEMPLATE_ID,
            vec![Record::OptionsData(options_data.to_data_record())],
        )?;

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

        // A set holds records of one template, so IPv4 and IPv6 flows go
        // in separate sets.
        let (ipv4, ipv6): (Vec<_>, Vec<_>) = flows
            .iter()
            .map(Flow::to_flow_data)
            .partition(|data| data.source_ip.is_ipv4());

        for chunk in ipv4
            .chunks(MAX_RECORDS_PER_SET)
            .chain(ipv6.chunks(MAX_RECORDS_PER_SET))
        {
            let records = chunk
                .iter()
                .map(|data| Record::Data(data.to_data_record()))
                .collect();
            self.send_data(chunk[0].template_id(), records)?;
        }

        Ok(())
    }

    /// Packet records vary in size, so a message is filled by bytes.
    fn send_packets(&mut self, packets: Vec<PacketData>) -> Result<()> {
        let mut records = Vec::new();
        let mut template_id = 0;
        let mut size = 0;
        let mut scratch = Vec::new();

        for packet in &packets {
            let record = packet.to_data_record();
            scratch.clear();
            record.encode(&mut scratch);
            let len = scratch.len();
            if !records.is_empty()
                && (size + len > MAX_SET_BODY || packet.template_id() != template_id)
            {
                self.send_data(template_id, std::mem::take(&mut records))?;
                size = 0;
            }
            template_id = packet.template_id();
            size += len;
            records.push(Record::Data(record));
        }
        if !records.is_empty() {
            self.send_data(template_id, records)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    use clap::Parser;
    use rustflow_core::ipfix::parser::{IpfixParser, Record as Parsed};

    use super::*;
    use crate::capture::Link;
    use crate::flow::FlowKey;

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

    fn packet(section_len: usize) -> PacketData {
        PacketData {
            link: Link::Ethernet,
            length: 1500,
            section: vec![0xab; section_len],
        }
    }

    fn flow() -> Flow {
        let mut flow = Flow::new(FlowKey {
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "10.0.0.2".parse().unwrap(),
            protocol: 6,
            source_port: 1,
            destination_port: 2,
        });
        flow.update(100, 0);
        flow
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

        let mut parser = IpfixParser::default();
        let sequence: Vec<u32> = datagrams(&receiver)
            .iter()
            .map(|message| parser.parse(message).unwrap().1.header.sequence_number)
            .collect();
        // Templates do not count; one options record, three packets, one
        // options record, one flow.
        assert_eq!(sequence, [0, 0, 1, 4, 5]);
        assert_eq!(exporter.sequence_number.load(Ordering::SeqCst), 6);
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
        let mut parser = IpfixParser::default();
        let mut records = 0;
        for message in &messages {
            let (_, parsed) = parser.parse(message).unwrap();
            records += parsed
                .sets
                .iter()
                .flat_map(|set| &set.records)
                .filter(|record| matches!(record, Parsed::Data(_)))
                .count();
            assert!(message.len() <= MAX_MESSAGE_SIZE);
        }
        assert_eq!(records, 25);
        // 131-byte records: ten per message; 1029-byte records: one each.
        assert_eq!(messages.len(), 1 + 2 + 5);
    }
}
