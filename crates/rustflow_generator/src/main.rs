use clap::{Args, Parser, ValueEnum, value_parser};
use ipnet::Ipv4Net;
use net::Ipv4Addr;
use std::net;
use std::ops::RangeInclusive;
use std::str::FromStr;

#[derive(Debug, Clone)]
enum Port {
    Range(RangeInclusive<u16>),
    Single(u16),
}

impl FromStr for Port {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.contains("-") {
            true => {
                let mut iter = s.split('-').map(|x| x.parse().unwrap());
                Ok(Port::Range(iter.next().unwrap()..=iter.next().unwrap()))
            }
            false => Ok(Port::Single(s.parse().unwrap())),
        }
    }
}

#[derive(Debug, Clone)]
enum Ip {
    Range(Ipv4Net),
    Single(Ipv4Addr),
}

impl FromStr for Ip {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.contains("/") {
            true => Ok(Ip::Range(s.parse().unwrap())),
            false => Ok(Ip::Single(s.parse().unwrap())),
        }
    }
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Cli {
    #[arg(short = 'v', value_enum)]
    version: Version,

    #[arg(long, default_value_t = true)]
    tcp: bool,

    #[arg(long, conflicts_with_all = ["tcp", "icmp"], default_value_t = false)]
    udp: bool,

    #[arg(long, conflicts_with_all = ["tcp", "udp"], default_value_t = false)]
    icmp: bool,

    #[command(flatten)]
    tcp_flags: TcpFlags,

    #[arg(long, value_parser = value_parser!(Ip))]
    src_ip: Option<Ip>,

    #[arg(long, value_parser = value_parser!(Ip))]
    dst_ip: Option<Ip>,

    #[arg(long, value_parser = value_parser!(Port))]
    src_port: Option<Port>,

    #[arg(long, value_parser = value_parser!(Port))]
    dst_port: Option<Port>,

    #[arg(long)]
    src_if: Option<u16>,

    #[arg(long)]
    dst_if: Option<u16>,

    #[arg(short = 's', long, default_value_t = 1)]
    sampling_interval: u16,

    #[arg(long, value_parser = value_parser!(Ipv4Addr), default_value = "127.0.0.1")]
    target: Ipv4Addr,

    #[arg(long, default_value_t = 2055)]
    port: u16,

    #[arg(long, default_value_t = 100)]
    speed: u32,
}

#[derive(Args, Debug)]
#[group(conflicts_with_all = ["udp", "icmp"])]
struct TcpFlags {
    #[arg(short = 'S', long, default_value_t = false)]
    syn: bool,

    #[arg(short = 'A', long, default_value_t = false)]
    ack: bool,

    #[arg(short = 'F', long, default_value_t = false)]
    fin: bool,

    #[arg(short = 'R', long, default_value_t = false)]
    rst: bool,

    #[arg(short = 'P', long, default_value_t = false)]
    push: bool,

    #[arg(short = 'U', long, default_value_t = false)]
    urg: bool,

    #[arg(short = 'E', long, default_value_t = false)]
    ece: bool,

    #[arg(short = 'C', long, default_value_t = false)]
    cwr: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Version {
    NetflowV5,
}

fn main() {
    let args = Cli::parse();

    println!("{:#?}", args);
}
