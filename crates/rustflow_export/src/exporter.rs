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

use crate::capture::CaptureStats;
use crate::flow::Flow;
use crate::ipfix::data::{
    OptionsData, PacketReport, SelectorReport, SequenceReport, SequenceStats,
};
use crate::ipfix::template::{
    FLOW_TEMPLATE_ID, OPTIONS_TEMPLATE_ID, PACKET_REPORT_TEMPLATE_ID, SELECTOR_TEMPLATE_ID,
    SEQUENCE_TEMPLATE_ID, STATS_TEMPLATE_ID, create_flow_template, create_options_template,
    create_packet_report_template, create_selector_template, create_sequence_template,
    create_stats_template,
};
use crate::{ExportArgs, ExportMode};

// Maximum data records per set
const MAX_RECORDS_PER_SET: usize = 30;

/// Byte budget for the data records of one IPFIX message, kept under a
/// typical 1500-byte MTU with headroom for the IPFIX and set headers.
const MAX_MESSAGE_PAYLOAD: usize = 1300;

/// This exporter runs a single primitive selector in a single selection
/// sequence.
pub const SELECTOR_ID: u64 = 1;
pub const SELECTION_SEQUENCE_ID: u64 = 1;

pub struct Exporter {
    socket: UdpSocket,
    args: ExportArgs,
    sequence_number: AtomicU32,
    last_template_send: Instant,
}

impl Exporter {
    pub fn new(args: ExportArgs) -> Result<Self> {
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

    fn send_message(&self, sets: Vec<Set>) -> Result<()> {
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
        self.socket.send_to(&encoded, self.args.collector_addr()?)?;
        Ok(())
    }

    pub fn send_templates(&mut self) -> Result<()> {
        info!("Sending templates to collector");

        let sets = match self.args.mode {
            ExportMode::Flows => vec![
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
            ExportMode::Packets => vec![
                Set {
                    id: IPFIX_TEMPLATE_SET_ID,
                    length: 0,
                    records: vec![Record::Template(create_packet_report_template())],
                },
                Set {
                    id: IPFIX_OPTIONS_TEMPLATE_SET_ID,
                    length: 0,
                    records: vec![
                        Record::OptionsTemplate(create_selector_template(
                            &self.args.sampling_config()?,
                        )),
                        Record::OptionsTemplate(create_sequence_template()),
                        Record::OptionsTemplate(create_stats_template()),
                    ],
                },
            ],
        };

        self.send_message(sets)?;
        self.last_template_send = Instant::now();
        debug!("Templates sent successfully");

        Ok(())
    }

    pub fn send_options_data(&mut self) -> Result<()> {
        debug!("Sending options data");

        let sets = match self.args.mode {
            ExportMode::Flows => {
                // The legacy record carries a flat 1-in-N rate; time-based
                // sampling has none, so nothing useful can be sent.
                let Some(rate) = self.args.sampling_config()?.effective_rate() else {
                    return Ok(());
                };
                let options_data = OptionsData::new(self.args.observation_domain_id, rate);
                vec![Set {
                    id: OPTIONS_TEMPLATE_ID,
                    length: 0,
                    records: vec![Record::OptionsData(options_data.to_data_record())],
                }]
            }
            ExportMode::Packets => {
                let selector = SelectorReport {
                    selector_id: SELECTOR_ID,
                    sampling: self.args.sampling_config()?,
                };
                let sequence = SequenceReport {
                    selection_sequence_id: SELECTION_SEQUENCE_ID,
                    ingress_interface: 0,
                    selector_id: SELECTOR_ID,
                };
                vec![
                    Set {
                        id: SELECTOR_TEMPLATE_ID,
                        length: 0,
                        records: vec![Record::OptionsData(selector.to_data_record())],
                    },
                    Set {
                        id: SEQUENCE_TEMPLATE_ID,
                        length: 0,
                        records: vec![Record::OptionsData(sequence.to_data_record())],
                    },
                ]
            }
        };

        self.send_message(sets)?;
        debug!("Options data sent successfully");

        Ok(())
    }

    /// Send a Selection Sequence Statistics Report Interpretation (RFC 5476
    /// section 6.5.3).
    pub fn send_stats(&mut self, stats: CaptureStats) -> Result<()> {
        debug!(
            "Sending selection sequence statistics: {} observed, {} selected",
            stats.packets_observed, stats.packets_selected
        );

        let record = SequenceStats {
            selection_sequence_id: SELECTION_SEQUENCE_ID,
            packets_observed: stats.packets_observed,
            packets_selected: stats.packets_selected,
        };

        self.send_message(vec![Set {
            id: STATS_TEMPLATE_ID,
            length: 0,
            records: vec![Record::OptionsData(record.to_data_record())],
        }])
    }

    /// Send PSAMP Packet Reports, split into MTU-sized IPFIX messages.
    pub fn send_packet_reports(&mut self, reports: &[PacketReport]) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }

        debug!("Exporting {} packet reports", reports.len());

        let mut batch: Vec<Record> = Vec::new();
        let mut batch_bytes = 0usize;

        for report in reports {
            let len = report.encoded_len();
            if !batch.is_empty() && batch_bytes + len > MAX_MESSAGE_PAYLOAD {
                self.flush_packet_reports(std::mem::take(&mut batch))?;
                batch_bytes = 0;
            }
            batch.push(Record::Data(report.to_data_record()));
            batch_bytes += len;
        }
        self.flush_packet_reports(batch)
    }

    fn flush_packet_reports(&mut self, records: Vec<Record>) -> Result<()> {
        let count = records.len() as u32;
        self.send_message(vec![Set {
            id: PACKET_REPORT_TEMPLATE_ID,
            length: 0,
            records,
        }])?;
        self.sequence_number.fetch_add(count, Ordering::SeqCst);
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
            self.socket.send_to(&encoded, collector_addr)?;

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
