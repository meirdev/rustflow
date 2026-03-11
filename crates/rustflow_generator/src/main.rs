//! IPFIX flow generator for testing collectors under load.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use clap::Parser;
use ipnet::Ipv4Net;
use rand::Rng;
use rustflow_core::common::InformationElement;

fn random_ip_in_cidr(cidr: &Ipv4Net, rng: &mut impl Rng) -> Ipv4Addr {
    let network = u32::from(cidr.network());
    let host_mask = u32::from(cidr.hostmask());
    if host_mask == 0 {
        return Ipv4Addr::from(network);
    }
    let host_bits = rng.random_range(1..host_mask);
    Ipv4Addr::from(network | host_bits)
}

#[derive(Debug, Clone)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        if parts.len() != 2 {
            return Err(format!("invalid port range: {s} (expected start-end)"));
        }
        let start: u16 = parts[0]
            .parse()
            .map_err(|e| format!("invalid start port: {e}"))?;
        let end: u16 = parts[1]
            .parse()
            .map_err(|e| format!("invalid end port: {e}"))?;
        if start > end {
            return Err(format!("start port {start} > end port {end}"));
        }
        Ok(Self { start, end })
    }

    fn random_port(&self, rng: &mut impl Rng) -> u16 {
        rng.random_range(self.start..=self.end)
    }
}
use rustflow_core::ipfix::encoder::Encode;
use rustflow_core::ipfix::parser::{
    DataRecord, FieldSpecifier, FieldValue, Header, IPFIX_OPTIONS_TEMPLATE_SET_ID,
    IPFIX_TEMPLATE_SET_ID, IPFIX_VERSION, IpfixPacket, Record, Set,
};

const FLOW_TEMPLATE_ID: u16 = 256;
const OPTIONS_TEMPLATE_ID: u16 = 257;

#[derive(Parser, Debug)]
#[command(name = "rustflow_generator")]
#[command(about = "IPFIX flow generator for testing")]
struct Args {
    /// Collector host address
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Collector port
    #[arg(short, long, default_value = "4739")]
    port: u16,

    /// Packets per second (0 = unlimited)
    #[arg(short = 'r', long, default_value = "1000")]
    rate: u32,

    /// Number of flows per packet
    #[arg(short = 'f', long, default_value = "10")]
    flows_per_packet: u16,

    /// Total packets to send (0 = infinite)
    #[arg(short = 'n', long, default_value = "0")]
    count: u64,

    /// Observation domain ID
    #[arg(long, default_value = "1")]
    observation_domain_id: u32,

    /// Template refresh interval in seconds
    #[arg(long, default_value = "30")]
    template_interval: u64,

    /// Source IP CIDR range (e.g. 10.0.0.0/8)
    #[arg(long, default_value = "10.0.0.0/8")]
    src_cidr: String,

    /// Destination IP CIDR range (e.g. 192.168.0.0/16)
    #[arg(long, default_value = "192.168.0.0/16")]
    dst_cidr: String,

    /// Comma-separated list of protocol numbers (e.g. 6,17 for TCP,UDP)
    #[arg(long, default_value = "6,17")]
    protocols: String,

    /// Source port range (e.g. 1024-65535)
    #[arg(long, default_value = "1024-65535")]
    src_port_range: String,

    /// Destination port range (e.g. 1-1024)
    #[arg(long, default_value = "1-1024")]
    dst_port_range: String,
}

// Static empty name for DataRecord fields
static EMPTY_NAME: std::sync::LazyLock<Arc<str>> = std::sync::LazyLock::new(|| Arc::from(""));

fn field_specifier(ie: InformationElement, length: u16) -> FieldSpecifier {
    FieldSpecifier {
        enterprise_bit: false,
        information_element_identifier: ie.into(),
        field_length: length,
        enterprise_number: None,
    }
}

fn create_flow_template() -> rustflow_core::ipfix::parser::TemplateRecord {
    use InformationElement::*;

    rustflow_core::ipfix::parser::TemplateRecord::new(
        FLOW_TEMPLATE_ID,
        vec![
            field_specifier(SourceIpv4Address, 4),
            field_specifier(DestinationIpv4Address, 4),
            field_specifier(ProtocolIdentifier, 1),
            field_specifier(SourceTransportPort, 2),
            field_specifier(DestinationTransportPort, 2),
            field_specifier(OctetDeltaCount, 8),
            field_specifier(PacketDeltaCount, 8),
            field_specifier(FlowStartMilliseconds, 8),
            field_specifier(FlowEndMilliseconds, 8),
        ],
    )
}

fn create_options_template() -> rustflow_core::ipfix::parser::OptionsTemplateRecord {
    use InformationElement::*;

    rustflow_core::ipfix::parser::OptionsTemplateRecord::new(
        OPTIONS_TEMPLATE_ID,
        1,
        vec![
            field_specifier(ObservationDomainId, 4),
            field_specifier(SamplingPacketInterval, 4),
        ],
    )
}

fn create_flow_record(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    octets: u64,
    packets: u64,
    flow_start: DateTime<Utc>,
    flow_end: DateTime<Utc>,
) -> DataRecord {
    use InformationElement::*;
    let name = EMPTY_NAME.clone();

    DataRecord(vec![
        (
            None,
            SourceIpv4Address.into(),
            name.clone(),
            FieldValue::Ipv4Address(src_ip),
        ),
        (
            None,
            DestinationIpv4Address.into(),
            name.clone(),
            FieldValue::Ipv4Address(dst_ip),
        ),
        (
            None,
            ProtocolIdentifier.into(),
            name.clone(),
            FieldValue::Unsigned8(protocol),
        ),
        (
            None,
            SourceTransportPort.into(),
            name.clone(),
            FieldValue::Unsigned16(src_port),
        ),
        (
            None,
            DestinationTransportPort.into(),
            name.clone(),
            FieldValue::Unsigned16(dst_port),
        ),
        (
            None,
            OctetDeltaCount.into(),
            name.clone(),
            FieldValue::Unsigned64(octets),
        ),
        (
            None,
            PacketDeltaCount.into(),
            name.clone(),
            FieldValue::Unsigned64(packets),
        ),
        (
            None,
            FlowStartMilliseconds.into(),
            name.clone(),
            FieldValue::DateTimeMilliseconds(flow_start),
        ),
        (
            None,
            FlowEndMilliseconds.into(),
            name,
            FieldValue::DateTimeMilliseconds(flow_end),
        ),
    ])
}

fn create_options_record(observation_domain_id: u32, sampling_interval: u32) -> DataRecord {
    use InformationElement::*;
    let name = EMPTY_NAME.clone();

    DataRecord(vec![
        (
            None,
            ObservationDomainId.into(),
            name.clone(),
            FieldValue::Unsigned32(observation_domain_id),
        ),
        (
            None,
            SamplingPacketInterval.into(),
            name,
            FieldValue::Unsigned32(sampling_interval),
        ),
    ])
}

struct IpfixGenerator {
    socket: UdpSocket,
    target: SocketAddr,
    observation_domain_id: u32,
    sequence_number: u32,
    flows_per_packet: u16,
    src_cidr: Ipv4Net,
    dst_cidr: Ipv4Net,
    protocols: Vec<u8>,
    src_port_range: PortRange,
    dst_port_range: PortRange,
}

impl IpfixGenerator {
    fn new(args: &Args) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let target: SocketAddr = format!("{}:{}", args.host, args.port).parse().unwrap();

        let src_cidr: Ipv4Net = args.src_cidr.parse().expect("invalid --src-cidr");
        let dst_cidr: Ipv4Net = args.dst_cidr.parse().expect("invalid --dst-cidr");
        let protocols: Vec<u8> = args
            .protocols
            .split(',')
            .map(|s| s.trim().parse::<u8>().expect("invalid protocol number"))
            .collect();
        if protocols.is_empty() {
            panic!("--protocols must contain at least one protocol number");
        }
        let src_port_range =
            PortRange::parse(&args.src_port_range).expect("invalid --src-port-range");
        let dst_port_range =
            PortRange::parse(&args.dst_port_range).expect("invalid --dst-port-range");

        Ok(Self {
            socket,
            target,
            observation_domain_id: args.observation_domain_id,
            sequence_number: 0,
            flows_per_packet: args.flows_per_packet,
            src_cidr,
            dst_cidr,
            protocols,
            src_port_range,
            dst_port_range,
        })
    }

    fn send_packet(&mut self, packet: &IpfixPacket) -> std::io::Result<usize> {
        let mut buf = Vec::new();
        packet.encode(&mut buf);
        self.socket.send_to(&buf, self.target)
    }

    fn send_templates(&mut self) -> std::io::Result<usize> {
        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0,
                export_time: Utc::now(),
                sequence_number: self.sequence_number,
                observation_domain_id: self.observation_domain_id,
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

        self.send_packet(&packet)
    }

    fn send_options(&mut self) -> std::io::Result<usize> {
        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0,
                export_time: Utc::now(),
                sequence_number: self.sequence_number,
                observation_domain_id: self.observation_domain_id,
            },
            sets: vec![Set {
                id: OPTIONS_TEMPLATE_ID,
                length: 0,
                records: vec![Record::OptionsData(create_options_record(
                    self.observation_domain_id,
                    1,
                ))],
            }],
        };

        self.send_packet(&packet)
    }

    fn send_data_packet(&mut self) -> std::io::Result<usize> {
        let mut rng = rand::rng();
        let now = Utc::now();

        let records: Vec<Record> = (0..self.flows_per_packet)
            .map(|_| {
                let src_ip = random_ip_in_cidr(&self.src_cidr, &mut rng);
                let dst_ip = random_ip_in_cidr(&self.dst_cidr, &mut rng);
                let protocol = self.protocols[rng.random_range(0..self.protocols.len())];
                let src_port = self.src_port_range.random_port(&mut rng);
                let dst_port = self.dst_port_range.random_port(&mut rng);
                let octets: u64 = rng.random_range(64..65536);
                let packets: u64 = rng.random_range(1..100);

                let flow_start =
                    now - chrono::Duration::milliseconds(rng.random_range(1000..60000));
                let flow_end = now - chrono::Duration::milliseconds(rng.random_range(0..1000));

                Record::Data(create_flow_record(
                    src_ip, dst_ip, protocol, src_port, dst_port, octets, packets, flow_start,
                    flow_end,
                ))
            })
            .collect();

        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0,
                export_time: now,
                sequence_number: self.sequence_number,
                observation_domain_id: self.observation_domain_id,
            },
            sets: vec![Set {
                id: FLOW_TEMPLATE_ID,
                length: 0,
                records,
            }],
        };

        self.sequence_number = self
            .sequence_number
            .wrapping_add(self.flows_per_packet as u32);
        self.send_packet(&packet)
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    eprintln!("IPFIX Generator");
    eprintln!("  Target: {}:{}", args.host, args.port);
    eprintln!(
        "  Rate: {} packets/sec",
        if args.rate == 0 {
            "unlimited".to_string()
        } else {
            args.rate.to_string()
        }
    );
    eprintln!("  Flows per packet: {}", args.flows_per_packet);
    eprintln!(
        "  Total packets: {}",
        if args.count == 0 {
            "infinite".to_string()
        } else {
            args.count.to_string()
        }
    );
    eprintln!("  Source CIDR: {}", args.src_cidr);
    eprintln!("  Destination CIDR: {}", args.dst_cidr);
    eprintln!("  Protocols: {}", args.protocols);
    eprintln!("  Source port range: {}", args.src_port_range);
    eprintln!("  Destination port range: {}", args.dst_port_range);
    eprintln!();

    let mut generator = IpfixGenerator::new(&args)?;

    generator.send_templates()?;
    generator.send_options()?;
    eprintln!("Sent initial templates and options");

    let packet_interval = if args.rate > 0 {
        Duration::from_secs_f64(1.0 / args.rate as f64)
    } else {
        Duration::ZERO
    };

    let template_interval = Duration::from_secs(args.template_interval);
    let mut last_template = Instant::now();
    let mut packets_sent: u64 = 0;
    let mut total_flows: u64 = 0;
    let start_time = Instant::now();
    let mut last_report = Instant::now();

    loop {
        let loop_start = Instant::now();

        if last_template.elapsed() >= template_interval {
            generator.send_templates()?;
            generator.send_options()?;
            last_template = Instant::now();
        }

        generator.send_data_packet()?;
        packets_sent += 1;
        total_flows += args.flows_per_packet as u64;

        if last_report.elapsed() >= Duration::from_secs(1) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let actual_rate = packets_sent as f64 / elapsed;
            let flow_rate = total_flows as f64 / elapsed;
            eprintln!(
                "Sent {} packets ({} flows) | {:.0} pps | {:.0} flows/sec",
                packets_sent, total_flows, actual_rate, flow_rate
            );
            last_report = Instant::now();
        }

        if args.count > 0 && packets_sent >= args.count {
            break;
        }

        if args.rate > 0 {
            let elapsed = loop_start.elapsed();
            if elapsed < packet_interval {
                std::thread::sleep(packet_interval - elapsed);
            }
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    eprintln!();
    eprintln!(
        "Done! Sent {} packets ({} flows) in {:.2}s",
        packets_sent, total_flows, elapsed
    );
    eprintln!(
        "Average rate: {:.0} packets/sec, {:.0} flows/sec",
        packets_sent as f64 / elapsed,
        total_flows as f64 / elapsed
    );

    Ok(())
}
