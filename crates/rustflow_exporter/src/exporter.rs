use std::net::UdpSocket;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use log::{debug, info};
use rustflow_core::ipfix::encoder::Encode;
use rustflow_core::ipfix::parser::{
    Header, IPFIX_OPTIONS_TEMPLATE_SET_ID, IPFIX_TEMPLATE_SET_ID, IPFIX_VERSION, IpfixPacket,
    Record, Set,
};

use crate::Args;
use crate::flow::Flow;
use crate::ipfix::data::OptionsData;
use crate::ipfix::template::{
    FLOW_TEMPLATE_ID, OPTIONS_TEMPLATE_ID, create_flow_template, create_options_template,
};

// Maximum data records per set
const MAX_RECORDS_PER_SET: usize = 30;

pub struct Exporter {
    socket: UdpSocket,
    args: Args,
    sequence_number: AtomicU32,
    last_template_send: Instant,
}

impl Exporter {
    pub fn new(args: Args) -> Result<Self> {
        let collector_addr = args.collector_addr()?;
        info!("Connecting to collector at {}", collector_addr);

        let socket = UdpSocket::bind("0.0.0.0:0")?;

        Ok(Self {
            socket,
            args,
            sequence_number: AtomicU32::new(0),
            last_template_send: Instant::now() - Duration::from_secs(9999), // Force initial send
        })
    }

    pub fn should_send_template(&self) -> bool {
        let elapsed = Instant::now().duration_since(self.last_template_send);
        elapsed >= Duration::from_secs(self.args.template_refresh_rate)
    }

    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0, // Will be calculated during encoding
                export_time: Utc::now(),
                sequence_number: self.sequence_number.load(Ordering::SeqCst),
                observation_domain_id: self.args.observation_domain_id,
            },
            sets: vec![
                Set {
                    id: IPFIX_TEMPLATE_SET_ID,
                    length: 0,
                    records: vec![Record::Template(create_flow_template())],
                },
                Set {
                    id: IPFIX_OPTIONS_TEMPLATE_SET_ID,
                    length: 0,
                    records: vec![Record::OptionsTemplate(create_options_template())],
                },
            ],
        };

        let mut encoded = Vec::new();
        packet.encode(&mut encoded);
        self.socket.send_to(&encoded, self.args.collector_addr()?)?;

        self.last_template_send = Instant::now();
        debug!("Templates sent successfully");

        Ok(())
    }

    pub fn send_options_data(&mut self) -> Result<()> {
        debug!("Sending options data");

        let options_data = OptionsData::new(
            self.args.observation_domain_id,
            self.args.sampling_packet_interval,
        );

        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0,
                export_time: Utc::now(),
                sequence_number: self.sequence_number.load(Ordering::SeqCst),
                observation_domain_id: self.args.observation_domain_id,
            },
            sets: vec![Set {
                id: OPTIONS_TEMPLATE_ID,
                length: 0,
                records: vec![Record::OptionsData(options_data.to_data_record())],
            }],
        };

        let mut encoded = Vec::new();
        packet.encode(&mut encoded);
        self.socket.send_to(&encoded, self.args.collector_addr()?)?;

        debug!("Options data sent successfully");

        Ok(())
    }

    pub fn send_flows(&mut self, flows: Vec<Flow>) -> Result<()> {
        if flows.is_empty() {
            return Ok(());
        }

        info!("Exporting {} flows", flows.len());

        let collector_addr = self.args.collector_addr()?;
        let mut total_exported = 0;
        let mut num_packets = 0;

        for chunk in flows.chunks(MAX_RECORDS_PER_SET) {
            let records: Vec<Record> = chunk
                .iter()
                .map(|flow| Record::Data(flow.to_flow_data().to_data_record()))
                .collect();

            let chunk_len = records.len() as u32;

            let packet = IpfixPacket {
                header: Header {
                    version: IPFIX_VERSION,
                    length: 0,
                    export_time: Utc::now(),
                    sequence_number: self.sequence_number.load(Ordering::SeqCst),
                    observation_domain_id: self.args.observation_domain_id,
                },
                sets: vec![Set {
                    id: FLOW_TEMPLATE_ID,
                    length: 0,
                    records,
                }],
            };

            let mut encoded = Vec::new();
            packet.encode(&mut encoded);
            self.socket.send_to(&encoded, &collector_addr)?;

            self.sequence_number.fetch_add(chunk_len, Ordering::SeqCst);
            total_exported += chunk_len;
            num_packets += 1;

            debug!(
                "Sent packet with {} flows ({} bytes)",
                chunk_len,
                encoded.len()
            );
        }

        debug!(
            "Exported {} flows in {} packets",
            total_exported, num_packets
        );

        Ok(())
    }
}
