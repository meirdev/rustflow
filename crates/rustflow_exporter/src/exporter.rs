use anyhow::Result;
use log::{debug, info};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::flow::Flow;
use crate::ipfix::data::{DataRecord, OptionsDataRecord};
use crate::ipfix::template::{create_flow_template, create_options_template};
use crate::ipfix::{IpfixMessage, FLOW_TEMPLATE_ID, OPTIONS_TEMPLATE_ID};

// IPFIX header (16 bytes) + Set header (4 bytes) = 20 bytes overhead per packet
const IPFIX_HEADER_SIZE: usize = 16;
const SET_HEADER_SIZE: usize = 4;
// Each flow record: 4+4+1+2+2+8+8+2+4 = 35 bytes
const FLOW_RECORD_SIZE: usize = 35;
// Target max UDP packet size (conservative to avoid fragmentation)
const MAX_PACKET_SIZE: usize = 1400;

pub struct Exporter {
    socket: UdpSocket,
    config: Config,
    sequence_number: AtomicU32,
    last_template_send: Instant,
}

impl Exporter {
    pub fn new(config: Config) -> Result<Self> {
        let collector_addr = config.exporter.collector_addr()?;
        info!("Connecting to collector at {}", collector_addr);

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        // socket.connect(collector_addr)?;

        Ok(Self {
            socket,
            config,
            sequence_number: AtomicU32::new(0),
            last_template_send: Instant::now() - Duration::from_secs(9999), // Force initial send
        })
    }

    pub fn should_send_template(&self) -> bool {
        let elapsed = Instant::now().duration_since(self.last_template_send);
        elapsed >= Duration::from_secs(self.config.template.refresh_rate)
    }

    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        let mut message = IpfixMessage::new(
            self.config.exporter.observation_domain_id,
            self.sequence_number.load(Ordering::SeqCst),
        );

        // Add flow template
        let flow_template = create_flow_template();
        message.add_set(flow_template.encode_as_set()?);

        // Add options template
        let options_template = create_options_template();
        message.add_set(options_template.encode_as_set()?);

        // Send message
        let encoded = message.encode()?;
        // self.socket.send(&encoded)?;
        self.socket.send_to(&encoded, self.config.exporter.collector_addr()?)?;

        self.last_template_send = Instant::now();
        debug!("Templates sent successfully");

        Ok(())
    }

    pub fn send_options_data(&mut self) -> Result<()> {
        debug!("Sending options data");

        let mut message = IpfixMessage::new(
            self.config.exporter.observation_domain_id,
            self.sequence_number.load(Ordering::SeqCst),
        );

        let options_data = OptionsDataRecord::new(
            OPTIONS_TEMPLATE_ID,
            self.config.exporter.observation_domain_id,
            self.config.options.sampling_packet_interval,
        );

        message.add_set(options_data.encode_as_set()?);

        let encoded = message.encode()?;
        // self.socket.send(&encoded)?;
        self.socket.send_to(&encoded, self.config.exporter.collector_addr()?)?;

        debug!("Options data sent successfully");

        Ok(())
    }

    pub fn send_flows(&mut self, flows: Vec<Flow>) -> Result<()> {
        if flows.is_empty() {
            return Ok(());
        }

        info!("Exporting {} flows", flows.len());

        // Calculate how many flows can fit in one packet
        let available_space = MAX_PACKET_SIZE - IPFIX_HEADER_SIZE - SET_HEADER_SIZE;
        let flows_per_packet = available_space / FLOW_RECORD_SIZE;

        let collector_addr = self.config.exporter.collector_addr()?;
        let mut total_exported = 0u32;

        // Split flows into chunks and send multiple packets
        for chunk in flows.chunks(flows_per_packet) {
            let mut message = IpfixMessage::new(
                self.config.exporter.observation_domain_id,
                self.sequence_number.load(Ordering::SeqCst),
            );

            let mut data_record = DataRecord::new(FLOW_TEMPLATE_ID);

            for flow in chunk {
                data_record.add_flow(flow.to_flow_data());
            }

            message.add_set(data_record.encode_as_set()?);

            let encoded = message.encode()?;
            self.socket.send_to(&encoded, &collector_addr)?;

            let chunk_len = data_record.len() as u32;
            self.sequence_number.fetch_add(chunk_len, Ordering::SeqCst);
            total_exported += chunk_len;

            debug!("Sent packet with {} flows ({} bytes)", chunk_len, encoded.len());
        }

        let num_packets = (flows.len() + flows_per_packet - 1) / flows_per_packet;
        debug!("Exported {} flows in {} packets", total_exported, num_packets);

        Ok(())
    }
}
