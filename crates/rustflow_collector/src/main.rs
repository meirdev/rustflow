use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;

use clap::{Parser, Subcommand};
use crossbeam::channel::{after, unbounded};
use crossbeam::select;
use pcap::{Activated, Capture, Device};
use rustc_hash::FxHashMap;
use rustflow_core::ipfix::fields::{EnterpriseNumber, FieldId, default_fields};
use rustflow_core::ipfix::parser::IpfixParser;
use rustflow_core::ipfix::types::DataValue;
use rustflow_core::utils::parse_udp_packet;

#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 't', long, value_parser = clap::builder::PossibleValuesParser::new(["ipfix", "sflow"]), help = "Type of flow data to collect", default_value = "ipfix")]
    pub r#type: String,

    #[arg(short = 'o', long, help = "Output directory for flow data")]
    pub output: Option<PathBuf>,

    #[arg(
        short = 'i',
        long,
        help = "Interval for flushing data to disk in seconds",
        default_value_t = 60
    )]
    pub interval: u64,

    #[arg(
        short = 'm',
        long,
        help = "Maximum number of flows to keep in memory before flushing to disk",
        default_value_t = 100000
    )]
    pub max_flows: u64,

    #[arg(
        long,
        help = "List of fields to include in the output, comma-separated",
        default_value = "octetDeltaCount,packetDeltaCount,sourceIPv4Address,destinationIPv4Address,sourceIPv6Address,destinationIPv6Address,sourceTransportPort,destinationTransportPort,protocolIdentifier,ipVersion,tcpControlBits,flowStartMilliseconds,flowEndMilliseconds,samplingInterval,samplerRandomInterval,samplingPacketInterval"
    )]
    pub fields: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Live {
        #[arg(
            short = 'i',
            help = "Network interface to capture traffic from",
            default_value = "any"
        )]
        interface: String,

        #[arg(short = 'b', help = "Host to bind to")]
        host: Option<String>,

        #[arg(short = 'p', help = "Port to bind to", default_value_t = 2055)]
        port: u16,
    },
    Pcap {
        #[arg(short = 'f', long)]
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let fields = default_fields();

    let selected_fields = cli.fields
        .split(',')
        .collect::<Vec<&str>>();

    let field_ids = selected_fields
        .iter()
        .map(|i| fields.get_id(i).unwrap())
        .collect::<Vec<(EnterpriseNumber, FieldId)>>();

    let header = selected_fields
        .clone()
        .iter()
        .map(|field| field.to_string())
        .collect::<Vec<String>>()
        .join(",");

    let (sender, receiver) = unbounded::<String>();

    thread::spawn(move || {
        let mut parsers: FxHashMap<IpAddr, IpfixParser> = FxHashMap::default();

        let mut cap: Capture<dyn Activated> = match cli.command {
            Commands::Live {
                interface,
                host,
                port,
            } => {
                let interfaces = Device::list().expect("Failed to list devices");

                let interface = interfaces
                    .into_iter()
                    .find(|d| d.name == interface)
                    .ok_or_else(|| format!("Could not find network interface: {}", interface))
                    .unwrap();

                let mut cap = Capture::from_device(interface)
                    .unwrap()
                    .immediate_mode(true)
                    .open()
                    .unwrap();

                let filter = if let Some(host) = &host {
                    format!("host {} and port {}", host, port)
                } else {
                    format!("port {}", port)
                };

                cap.filter(&filter, true)
                    .expect("Failed to set filter on capture");

                cap.into()
            }
            Commands::Pcap { file } => Capture::from_file(file)
                .expect("Failed to open pcap file")
                .into(),
        };

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let time_received = chrono::Utc::now();

                    if let Ok((src, payload)) = parse_udp_packet(&packet.data) {
                        if !parsers.contains_key(&src) {
                            parsers.insert(src, IpfixParser::new(fields.clone()));
                        }

                        let parser = parsers.get_mut(&src).unwrap();

                        if let Ok(data_records) = parser.parse_data_records(&payload) {
                            for record in data_records.into_iter() {
                                let line = field_ids
                                    .iter()
                                    .map(|field| {
                                        record
                                            .get(field)
                                            .or(parser.options.get(field))
                                            .unwrap_or(&DataValue::Null)
                                            .to_string()
                                    })
                                    .collect::<Vec<String>>()
                                    .join(",");

                                sender.send(line).expect("Failed to send message");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading packet: {}", e);
                    continue;
                }
            }
        }
    });

    if let Some(output) = cli.output {
        let mut flows: Vec<String> = Vec::with_capacity(cli.max_flows as usize);

        if !output.exists() {
            std::fs::create_dir_all(&output).expect("Failed to create output directory");
        }

        loop {
            let timeout_receiver = after(Duration::from_secs(cli.interval));

            loop {
                select! {
                    recv(receiver) -> msg => {
                        flows.push(msg.expect("Failed to receive message"));

                        if flows.len() >= cli.max_flows as usize {
                            break;
                        }
                    }
                    recv(timeout_receiver) -> _ => {
                        break;
                    }
                }
            }

            let timestamp = chrono::Utc::now().format("%Y%m%d%s%6f").to_string();

            let filename = output.join(format!("flows_{}.csv", timestamp));

            let file = File::options()
                .write(true)
                .create(true)
                .open(filename)
                .unwrap();

            let mut file = BufWriter::new(file);

            writeln!(file, "{}", header).unwrap();

            for flow in &flows {
                writeln!(file, "{}", flow).unwrap();
            }

            file.flush().unwrap();

            flows.clear();
        }
    } else {
        while let Ok(line) = receiver.recv() {
            println!("{}", line);
        }
    }
}
