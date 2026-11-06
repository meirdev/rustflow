//! `rustflow generate`: synthetic flows in the protocol of choice, for
//! testing a collector under load.

use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use etherparse::PacketBuilder;
use ipnet::IpNet;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use rand::Rng;
use rand::distr::uniform::SampleUniform;
use rand::seq::IndexedRandom;
use rustflow_core_new::convert::{Elements, Protocol, Record, Scope};
use rustflow_core_new::export;
use rustflow_core_new::protocol::information_element::iana;
use rustflow_core_new::protocol::value::Value;
use rustflow_core_new::protocol::{ipfix, netflow_v5, netflow_v9, sflow_v5};

const IPPROTO_TCP: u8 = 6;

/// Arguments for the `generate` subcommand.
#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Collector host address
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Collector port
    #[arg(short, long, default_value = "4739")]
    port: u16,

    /// Write the packets to a pcap file instead of sending them
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Flow protocol to generate
    #[arg(short = 'P', long, value_enum, default_value_t = Flavor::Ipfix)]
    protocol: Flavor,

    /// Packets per second (0 = unlimited)
    #[arg(short = 'r', long, default_value = "1000")]
    rate: u32,

    /// Number of flows per packet
    #[arg(short = 'f', long, default_value = "10")]
    flows_per_packet: u16,

    /// Total packets to send (0 = infinite)
    #[arg(short = 'n', long, default_value = "0")]
    count: u64,

    /// Observation domain ID (NetFlow v9 source ID, sFlow sub-agent ID)
    #[arg(long, default_value = "1")]
    observation_domain_id: u32,

    /// Template refresh interval in seconds (NetFlow v9 and IPFIX)
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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    NetflowV5,
    NetflowV9,
    Ipfix,
    Sflow,
}

impl fmt::Display for Flavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NetflowV5 => "NetFlow v5",
            Self::NetflowV9 => "NetFlow v9",
            Self::Ipfix => "IPFIX",
            Self::Sflow => "sFlow",
        })
    }
}

/// The exporter of the protocol chosen, the records to datagrams.
enum Generator {
    NetflowV5(export::netflow_v5::Exporter),
    NetflowV9(export::netflow_v9::Exporter),
    Ipfix(export::ipfix::Exporter),
    Sflow(export::sflow_v5::Agent),
}

impl Generator {
    fn new(args: &GenerateArgs) -> Self {
        // An uptime that has been counting for a while, as a device's has.
        let boot = SystemTime::now() - Duration::from_secs(3600);
        let domain = args.observation_domain_id;
        match args.protocol {
            Flavor::NetflowV5 => Self::NetflowV5(export::netflow_v5::Exporter::new(boot)),
            Flavor::NetflowV9 => Self::NetflowV9(export::netflow_v9::Exporter::new(domain, boot)),
            Flavor::Ipfix => Self::Ipfix(export::ipfix::Exporter::new(domain)),
            Flavor::Sflow => {
                let agent_address = match args.src_cidr {
                    IpNet::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    IpNet::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                };
                Self::Sflow(export::sflow_v5::Agent::new(agent_address, domain, boot))
            }
        }
    }

    /// Whether the protocol sends templates, and options records with
    /// them.
    fn templated(&self) -> bool {
        matches!(self, Self::NetflowV9(_) | Self::Ipfix(_))
    }

    fn resend_templates(&mut self) {
        match self {
            Self::NetflowV9(exporter) => exporter.resend_templates(),
            Self::Ipfix(exporter) => exporter.resend_templates(),
            Self::NetflowV5(_) | Self::Sflow(_) => {}
        }
    }

    fn write(
        &mut self,
        records: &[Record],
        now: SystemTime,
        datagram: &mut Vec<u8>,
    ) -> anyhow::Result<()> {
        datagram.clear();
        match self {
            Self::NetflowV5(exporter) => {
                netflow_v5::write(&exporter.export(records, now)?, datagram)?;
            }
            Self::NetflowV9(exporter) => {
                netflow_v9::write(&exporter.export(records, now)?, datagram)?;
            }
            Self::Ipfix(exporter) => ipfix::write(&exporter.export(records, now)?, datagram)?,
            Self::Sflow(agent) => sflow_v5::write(&agent.export(records, now)?, datagram)?,
        }
        Ok(())
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

fn address(ip: IpAddr) -> Value {
    match ip {
        IpAddr::V4(ip) => Value::Ipv4Address(ip),
        IpAddr::V6(ip) => Value::Ipv6Address(ip),
    }
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

/// Random flows within the ranges given, all of one shape.
struct Flows<'a> {
    args: &'a GenerateArgs,
    elements: Arc<Elements>,
    rng: rand::rngs::ThreadRng,
}

impl<'a> Flows<'a> {
    fn new(args: &'a GenerateArgs) -> io::Result<Self> {
        let (source, destination) = match (args.src_cidr, args.dst_cidr) {
            (IpNet::V4(_), IpNet::V4(_)) => {
                (iana::SOURCE_IPV4_ADDRESS, iana::DESTINATION_IPV4_ADDRESS)
            }
            (IpNet::V6(_), IpNet::V6(_)) => {
                (iana::SOURCE_IPV6_ADDRESS, iana::DESTINATION_IPV6_ADDRESS)
            }
            _ => {
                return Err(invalid_input(
                    "--src-cidr and --dst-cidr must use the same IP address family".to_string(),
                ));
            }
        };
        if args.protocols.is_empty() {
            return Err(invalid_input(
                "--protocols must contain at least one protocol number".to_string(),
            ));
        }
        if args.protocol == Flavor::NetflowV5 && source == iana::SOURCE_IPV6_ADDRESS {
            return Err(invalid_input(
                "NetFlow v5 carries IPv4 flows only".to_string(),
            ));
        }
        let elements = Arc::new(Elements::from(vec![
            source,
            destination,
            iana::PROTOCOL_IDENTIFIER,
            iana::TCP_CONTROL_BITS,
            iana::SOURCE_TRANSPORT_PORT,
            iana::DESTINATION_TRANSPORT_PORT,
            iana::OCTET_DELTA_COUNT,
            iana::PACKET_DELTA_COUNT,
            iana::FLOW_START_MILLISECONDS,
            iana::FLOW_END_MILLISECONDS,
        ]));
        Ok(Self {
            args,
            elements,
            rng: rand::rng(),
        })
    }

    fn next(&mut self, now_ms: u64) -> Record {
        let args = self.args;
        let rng = &mut self.rng;
        let protocol = *args.protocols.choose(rng).expect("checked when made");
        let tcp_flags = if protocol == IPPROTO_TCP {
            args.tcp_flags.choose(rng).copied().unwrap_or(0)
        } else {
            0
        };
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::clone(&self.elements),
            values: vec![
                address(random_ip_in_cidr(&args.src_cidr, rng)),
                address(random_ip_in_cidr(&args.dst_cidr, rng)),
                Value::Unsigned8(protocol),
                Value::Unsigned16(tcp_flags),
                Value::Unsigned16(args.src_port_range.sample(rng)),
                Value::Unsigned16(args.dst_port_range.sample(rng)),
                Value::Unsigned64(u64::from(args.octet_range.sample(rng))),
                Value::Unsigned64(u64::from(args.packet_range.sample(rng))),
                Value::DateTimeMilliseconds(now_ms - rng.random_range(1_000..60_000)),
                Value::DateTimeMilliseconds(now_ms - rng.random_range(0..1_000)),
            ],
        }
    }

    /// The options record saying the domain's packets are not sampled.
    fn options(&self) -> Record {
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: vec![(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(self.args.observation_domain_id),
            )],
            elements: Arc::new(Elements::from(vec![iana::SAMPLING_PACKET_INTERVAL])),
            values: vec![Value::Unsigned32(1)],
        }
    }
}

/// Where the datagrams go: a collector, or a capture file of what a
/// collector would have received.
enum Output {
    Socket {
        socket: UdpSocket,
        target: SocketAddr,
    },
    Pcap {
        writer: PcapWriter<BufWriter<File>>,
        target: SocketAddr,
    },
}

impl Output {
    fn open(args: &GenerateArgs) -> io::Result<Self> {
        // `--host` may be an IP address or a hostname (e.g. a compose service).
        let target: SocketAddr = (args.host.as_str(), args.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                invalid_input(format!(
                    "cannot resolve collector address {}:{}",
                    args.host, args.port
                ))
            })?;
        match &args.output {
            Some(path) => {
                let file = BufWriter::new(File::create(path)?);
                let writer = PcapWriter::new(file).map_err(io::Error::other)?;
                Ok(Self::Pcap { writer, target })
            }
            None => {
                let socket = UdpSocket::bind(if target.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })?;
                Ok(Self::Socket { socket, target })
            }
        }
    }

    fn send(&mut self, datagram: &[u8], now: SystemTime) -> io::Result<()> {
        match self {
            Self::Socket { socket, target } => socket.send_to(datagram, *target).map(drop),
            Self::Pcap { writer, target } => {
                let frame = frame(*target, datagram)?;
                let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default();
                let length = u32::try_from(frame.len())
                    .map_err(|_| invalid_input(format!("frame of {} bytes", frame.len())))?;
                writer
                    .write_packet(&PcapPacket::new(timestamp, length, &frame))
                    .map(drop)
                    .map_err(io::Error::other)
            }
        }
    }
}

/// An Ethernet frame carrying `datagram` to `target` from a documentation
/// address, as a capture of the generator's traffic would hold.
fn frame(target: SocketAddr, datagram: &[u8]) -> io::Result<Vec<u8>> {
    const SOURCE_PORT: u16 = 49152;
    let ethernet = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
    let mut frame = Vec::new();
    match target.ip() {
        IpAddr::V4(ip) => ethernet
            .ipv4([192, 0, 2, 1], ip.octets(), 64)
            .udp(SOURCE_PORT, target.port())
            .write(&mut frame, datagram)
            .map_err(io::Error::other)?,
        IpAddr::V6(ip) => ethernet
            .ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ip.octets(),
                64,
            )
            .udp(SOURCE_PORT, target.port())
            .write(&mut frame, datagram)
            .map_err(io::Error::other)?,
    }
    Ok(frame)
}

fn join<T: fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Run the flow generator.
pub fn run(args: GenerateArgs) -> anyhow::Result<()> {
    let mut flows = Flows::new(&args)?;
    let mut output = Output::open(&args)?;
    let mut generator = Generator::new(&args);

    println!("{} Generator", args.protocol);
    match &args.output {
        Some(path) => println!("  Output: {}", path.display()),
        None => println!("  Target: {}:{}", args.host, args.port),
    }
    println!(
        "  Rate: {} packets/sec",
        if args.rate == 0 {
            "unlimited".to_string()
        } else {
            args.rate.to_string()
        }
    );
    println!("  Flows per packet: {}", args.flows_per_packet);
    println!(
        "  Total packets: {}",
        if args.count == 0 {
            "infinite".to_string()
        } else {
            args.count.to_string()
        }
    );
    println!("  Source CIDR: {}", args.src_cidr);
    println!("  Destination CIDR: {}", args.dst_cidr);
    println!("  Protocols: {}", join(&args.protocols));
    println!("  Source port range: {}", args.src_port_range);
    println!("  Destination port range: {}", args.dst_port_range);
    println!("  TCP flag choices: {}", join(&args.tcp_flags));
    println!("  Octet range: {}", args.octet_range);
    println!("  Packet range: {}", args.packet_range);
    println!();

    let packet_interval = if args.rate > 0 {
        Duration::from_secs_f64(1.0 / f64::from(args.rate))
    } else {
        Duration::ZERO
    };
    let template_interval = Duration::from_secs(args.template_interval);
    let mut last_template: Option<Instant> = None;
    let mut packets_sent: u64 = 0;
    let mut total_flows: u64 = 0;
    let start_time = Instant::now();
    let mut last_report = Instant::now();
    let mut next_deadline = Instant::now();
    let mut records = Vec::with_capacity(usize::from(args.flows_per_packet) + 1);
    let mut datagram = Vec::new();

    loop {
        let now = SystemTime::now();
        let now_ms = unix_millis(now);
        records.clear();
        // Templates and the options record go out together, at the start
        // and then every template interval.
        if generator.templated() && last_template.is_none_or(|at| at.elapsed() >= template_interval)
        {
            generator.resend_templates();
            records.push(flows.options());
            last_template = Some(Instant::now());
        }
        for _ in 0..args.flows_per_packet {
            records.push(flows.next(now_ms));
        }
        generator.write(&records, now, &mut datagram)?;
        output.send(&datagram, now)?;
        packets_sent += 1;
        total_flows += u64::from(args.flows_per_packet);

        if last_report.elapsed() >= Duration::from_secs(1) {
            let elapsed = start_time.elapsed().as_secs_f64();
            println!(
                "Sent {} packets ({} flows) | {:.0} pps | {:.0} flows/sec",
                packets_sent,
                total_flows,
                packets_sent as f64 / elapsed,
                total_flows as f64 / elapsed
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
    println!();
    println!("Done! Sent {packets_sent} packets ({total_flows} flows) in {elapsed:.2}s");
    println!(
        "Average rate: {:.0} packets/sec, {:.0} flows/sec",
        packets_sent as f64 / elapsed,
        total_flows as f64 / elapsed
    );

    Ok(())
}
