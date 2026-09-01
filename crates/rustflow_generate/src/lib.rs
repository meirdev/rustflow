//! IPFIX flow generator for testing collectors under load.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use clap::Args as ClapArgs;
use ipnet::IpNet;
use rand::Rng;
use rand::distr::uniform::SampleUniform;
use rand::seq::IndexedRandom;
use rustflow_core::common::InformationElement;
use rustflow_core::ipfix::encoder::Encode;
use rustflow_core::ipfix::parser::{
    DataRecord, FieldSpecifier, FieldValue, Header, IPFIX_OPTIONS_TEMPLATE_SET_ID,
    IPFIX_TEMPLATE_SET_ID, IPFIX_VERSION, IpfixPacket, Record, Set, TemplateRecord,
};

const FLOW_TEMPLATE_ID: u16 = 256;
const OPTIONS_TEMPLATE_ID: u16 = 257;

const IPPROTO_TCP: u8 = 6;

fn random_ip_in_cidr(cidr: &IpNet, rng: &mut impl Rng) -> IpAddr {
    match cidr {
        IpNet::V4(cidr) => {
            let host_bits = rng.random::<u32>() & u32::from(cidr.hostmask());
            IpAddr::V4(Ipv4Addr::from(u32::from(cidr.network()) | host_bits))
        }
        IpNet::V6(cidr) => {
            let host_bits = rng.random::<u128>() & u128::from(cidr.hostmask());
            IpAddr::V6(Ipv6Addr::from(u128::from(cidr.network()) | host_bits))
        }
    }
}

fn parse_protocol(value: &str) -> Result<u8, String> {
    value
        .trim()
        .parse::<u8>()
        .map_err(|_| format!("invalid protocol number '{}'", value.trim()))
}

fn parse_tcp_flag(value: &str) -> Result<u16, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(0),
        "fin" => Ok(0x001),
        "syn" => Ok(0x002),
        "rst" => Ok(0x004),
        "psh" => Ok(0x008),
        "ack" => Ok(0x010),
        "urg" => Ok(0x020),
        "ece" => Ok(0x040),
        "cwr" => Ok(0x080),
        "ns" => Ok(0x100),
        value => value
            .parse::<u16>()
            .map_err(|_| format!("invalid TCP flag '{value}'")),
    }
}

#[derive(Debug, Clone, Copy)]
struct InclusiveRange<T> {
    start: T,
    end: T,
}

impl<T> FromStr for InclusiveRange<T>
where
    T: FromStr + PartialOrd + fmt::Display,
    T::Err: fmt::Display,
{
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (start, end) = s
            .split_once('-')
            .ok_or_else(|| format!("invalid range '{s}' (expected start-end)"))?;
        let start = start
            .trim()
            .parse::<T>()
            .map_err(|e| format!("invalid range start: {e}"))?;
        let end = end
            .trim()
            .parse::<T>()
            .map_err(|e| format!("invalid range end: {e}"))?;
        if start > end {
            return Err(format!("range start {start} > end {end}"));
        }
        Ok(Self { start, end })
    }
}

impl<T: fmt::Display> fmt::Display for InclusiveRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl<T: SampleUniform + PartialOrd + Copy> InclusiveRange<T> {
    fn sample(&self, rng: &mut impl Rng) -> T {
        rng.random_range(self.start..=self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn of(cidr: &IpNet) -> Self {
        match cidr {
            IpNet::V4(_) => Self::V4,
            IpNet::V6(_) => Self::V6,
        }
    }
}

/// Arguments for the `generate` subcommand.
#[derive(ClapArgs, Debug)]
pub struct GenerateArgs {
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

    /// Source IP CIDR range (e.g. 10.0.0.0/8 or 2001:db8::/32)
    #[arg(long, default_value = "10.0.0.0/8")]
    src_cidr: IpNet,

    /// Destination IP CIDR range (same address family as --src-cidr)
    #[arg(long, default_value = "192.168.0.0/16")]
    dst_cidr: IpNet,

    /// Comma-separated list of protocol numbers (e.g. 6,17 for TCP,UDP)
    #[arg(long, default_value = "6,17", value_delimiter = ',', value_parser = parse_protocol)]
    protocols: Vec<u8>,

    /// Source port range (e.g. 1024-65535)
    #[arg(long, default_value = "1024-65535")]
    src_port_range: InclusiveRange<u16>,

    /// Destination port range (e.g. 1-1024)
    #[arg(long, default_value = "1-1024")]
    dst_port_range: InclusiveRange<u16>,

    /// Comma-separated TCP flag choices (names or values, e.g. syn,ack,18)
    #[arg(long, default_value = "0", value_delimiter = ',', value_parser = parse_tcp_flag)]
    tcp_flags: Vec<u16>,

    /// Octet count range per flow (e.g. 64-65535)
    #[arg(long, default_value = "64-65535")]
    octet_range: InclusiveRange<u16>,

    /// Packet count range per flow (e.g. 1-99)
    #[arg(long, default_value = "1-99")]
    packet_range: InclusiveRange<u16>,
}

fn create_flow_template(family: AddressFamily) -> TemplateRecord {
    use InformationElement::*;

    let (source_address, destination_address, address_length) = match family {
        AddressFamily::V4 => (SourceIpv4Address, DestinationIpv4Address, 4),
        AddressFamily::V6 => (SourceIpv6Address, DestinationIpv6Address, 16),
    };

    TemplateRecord::new(
        FLOW_TEMPLATE_ID,
        vec![
            FieldSpecifier::from_ie(source_address, address_length),
            FieldSpecifier::from_ie(destination_address, address_length),
            FieldSpecifier::from_ie(ProtocolIdentifier, 1),
            FieldSpecifier::from_ie(TcpControlBits, 2),
            FieldSpecifier::from_ie(SourceTransportPort, 2),
            FieldSpecifier::from_ie(DestinationTransportPort, 2),
            FieldSpecifier::from_ie(OctetDeltaCount, 8),
            FieldSpecifier::from_ie(PacketDeltaCount, 8),
            FieldSpecifier::from_ie(FlowStartMilliseconds, 8),
            FieldSpecifier::from_ie(FlowEndMilliseconds, 8),
        ],
    )
}

fn address_field(
    ip: IpAddr,
    v4: InformationElement,
    v6: InformationElement,
) -> (InformationElement, FieldValue) {
    match ip {
        IpAddr::V4(addr) => (v4, FieldValue::Ipv4Address(addr)),
        IpAddr::V6(addr) => (v6, FieldValue::Ipv6Address(addr)),
    }
}

fn create_options_template() -> rustflow_core::ipfix::parser::OptionsTemplateRecord {
    use InformationElement::*;

    rustflow_core::ipfix::parser::OptionsTemplateRecord::new(
        OPTIONS_TEMPLATE_ID,
        1,
        vec![
            FieldSpecifier::from_ie(ObservationDomainId, 4),
            FieldSpecifier::from_ie(SamplingPacketInterval, 4),
        ],
    )
}

struct Flow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    tcp_flags: u16,
    src_port: u16,
    dst_port: u16,
    octets: u16,
    packets: u16,
    flow_start: DateTime<Utc>,
    flow_end: DateTime<Utc>,
}

fn create_flow_record(flow: &Flow) -> DataRecord {
    use InformationElement::*;

    let (_, source_value) = address_field(flow.src_ip, SourceIpv4Address, SourceIpv6Address);
    let (_, destination_value) =
        address_field(flow.dst_ip, DestinationIpv4Address, DestinationIpv6Address);

    DataRecord::new(vec![
        source_value,
        destination_value,
        FieldValue::Unsigned8(flow.protocol),
        FieldValue::Unsigned16(flow.tcp_flags),
        FieldValue::Unsigned16(flow.src_port),
        FieldValue::Unsigned16(flow.dst_port),
        FieldValue::Unsigned64(u64::from(flow.octets)),
        FieldValue::Unsigned64(u64::from(flow.packets)),
        FieldValue::DateTimeMilliseconds(flow.flow_start),
        FieldValue::DateTimeMilliseconds(flow.flow_end),
    ])
}

fn create_options_record(observation_domain_id: u32, sampling_interval: u32) -> DataRecord {
    DataRecord::new(vec![
        FieldValue::Unsigned32(observation_domain_id),
        FieldValue::Unsigned32(sampling_interval),
    ])
}

struct IpfixGenerator {
    socket: UdpSocket,
    target: SocketAddr,
    observation_domain_id: u32,
    sequence_number: u32,
    flows_per_packet: u16,
    family: AddressFamily,
    src_cidr: IpNet,
    dst_cidr: IpNet,
    protocols: Vec<u8>,
    tcp_flags: Vec<u16>,
    octet_range: InclusiveRange<u16>,
    packet_range: InclusiveRange<u16>,
    src_port_range: InclusiveRange<u16>,
    dst_port_range: InclusiveRange<u16>,
}

fn invalid_input(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

impl IpfixGenerator {
    fn new(args: &GenerateArgs) -> std::io::Result<Self> {
        let family = AddressFamily::of(&args.src_cidr);
        if AddressFamily::of(&args.dst_cidr) != family {
            return Err(invalid_input(
                "--src-cidr and --dst-cidr must use the same IP address family".to_string(),
            ));
        }
        if args.protocols.is_empty() {
            return Err(invalid_input(
                "--protocols must contain at least one protocol number".to_string(),
            ));
        }

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let target: SocketAddr = format!("{}:{}", args.host, args.port).parse().unwrap();

        Ok(Self {
            socket,
            target,
            observation_domain_id: args.observation_domain_id,
            sequence_number: 0,
            flows_per_packet: args.flows_per_packet,
            family,
            src_cidr: args.src_cidr,
            dst_cidr: args.dst_cidr,
            protocols: args.protocols.clone(),
            tcp_flags: args.tcp_flags.clone(),
            octet_range: args.octet_range,
            packet_range: args.packet_range,
            src_port_range: args.src_port_range,
            dst_port_range: args.dst_port_range,
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
                    records: vec![Record::Template(create_flow_template(self.family))],
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
                let tcp_flags = if protocol == IPPROTO_TCP {
                    self.tcp_flags.choose(&mut rng).copied().unwrap_or(0)
                } else {
                    0
                };
                let src_port = self.src_port_range.sample(&mut rng);
                let dst_port = self.dst_port_range.sample(&mut rng);
                let octets = self.octet_range.sample(&mut rng);
                let packets = self.packet_range.sample(&mut rng);

                let flow_start =
                    now - chrono::Duration::milliseconds(rng.random_range(1000..60000));
                let flow_end = now - chrono::Duration::milliseconds(rng.random_range(0..1000));

                Record::Data(create_flow_record(&Flow {
                    src_ip,
                    dst_ip,
                    protocol,
                    tcp_flags,
                    src_port,
                    dst_port,
                    octets,
                    packets,
                    flow_start,
                    flow_end,
                }))
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

fn join<T: fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Run the IPFIX flow generator.
pub fn run(args: GenerateArgs) -> std::io::Result<()> {
    let mut generator = IpfixGenerator::new(&args)?;

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
    eprintln!("  Protocols: {}", join(&args.protocols));
    eprintln!("  Source port range: {}", args.src_port_range);
    eprintln!("  Destination port range: {}", args.dst_port_range);
    eprintln!("  TCP flag choices: {}", join(&args.tcp_flags));
    eprintln!("  Octet range: {}", args.octet_range);
    eprintln!("  Packet range: {}", args.packet_range);
    eprintln!();

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

    let mut next_deadline = Instant::now();

    loop {
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
            // Absolute-deadline pacing: thread::sleep overshoots by tens of
            // microseconds, which caps a naive per-packet sleep at ~10k pps.
            // Scheduling against an absolute deadline self-corrects (a late
            // packet shortens the next wait), and the final stretch before
            // the deadline is busy-spun for precision.
            next_deadline += packet_interval;
            loop {
                let now = Instant::now();
                if now >= next_deadline {
                    break;
                }
                let remaining = next_deadline - now;
                if remaining > Duration::from_micros(200) {
                    std::thread::sleep(remaining - Duration::from_micros(150));
                } else {
                    std::hint::spin_loop();
                }
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
