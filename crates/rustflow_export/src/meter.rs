use std::net::SocketAddr;

use crate::ExportArgs;
use crate::capture::{Frame, Link};
use crate::flow::parse::{PacketInfo, parse};
use crate::flow::{Flow, FlowCache};
use crate::ipfix::data::PacketData;
use crate::sampler::Sampler;

/// Packets pending before they are exported without waiting for the timer.
const PACKET_BATCH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Aggregate the sampled packets into flows
    Flow,
    /// Export the start of every sampled packet
    Packet,
}

pub enum Records {
    Flows(Vec<Flow>),
    Packets(Vec<PacketData>),
}

enum Output {
    Flows(FlowCache),
    Packets {
        clip_length: usize,
        pending: Vec<PacketData>,
    },
}

const UDP: u8 = 17;

pub struct Meter {
    link: Link,
    /// The exporter's own datagrams, from `source` to `collector`, are not
    /// metered: on the capture interface each would produce more of them.
    source: SocketAddr,
    collector: SocketAddr,
    sampler: Sampler,
    output: Output,
}

impl Meter {
    pub fn new(args: &ExportArgs, link: Link, source: SocketAddr, collector: SocketAddr) -> Self {
        let output = match args.mode {
            Mode::Flow => Output::Flows(FlowCache::new(args.active_timeout, args.inactive_timeout)),
            Mode::Packet => Output::Packets {
                clip_length: usize::from(args.clip_length),
                pending: Vec::with_capacity(PACKET_BATCH),
            },
        };
        Self {
            link,
            source,
            collector,
            sampler: Sampler::new(args.sampling()),
            output,
        }
    }

    fn is_export(&self, packet: &PacketInfo) -> bool {
        let key = &packet.flow_key;
        key.protocol == UDP
            && key.source_ip == self.source.ip()
            && key.source_port == self.source.port()
            && key.destination_ip == self.collector.ip()
            && key.destination_port == self.collector.port()
    }

    pub fn observe(&mut self, frame: &Frame<'_>) {
        if !self.sampler.select() {
            return;
        }
        let packet = parse(self.link, frame.data);
        if packet.as_ref().is_some_and(|packet| self.is_export(packet)) {
            return;
        }
        match &mut self.output {
            Output::Flows(cache) => {
                if let Some(packet) = packet {
                    cache.update_flow(packet.flow_key, packet.packet_size, packet.tcp_flags);
                }
            }
            Output::Packets {
                clip_length,
                pending,
            } => pending.push(PacketData {
                link: self.link,
                length: frame.length,
                section: frame.data[..frame.data.len().min(*clip_length)].to_vec(),
            }),
        }
    }

    /// Whether records should be exported before the next timer tick.
    pub fn is_full(&self) -> bool {
        match &self.output {
            Output::Flows(_) => false,
            Output::Packets { pending, .. } => pending.len() >= PACKET_BATCH,
        }
    }

    /// The records due for export: the flows that expired, or every
    /// pending packet.
    pub fn take_due(&mut self) -> Records {
        match &mut self.output {
            Output::Flows(cache) => Records::Flows(cache.check_expired_flows()),
            Output::Packets { pending, .. } => Records::Packets(std::mem::take(pending)),
        }
    }

    /// Everything left, at shutdown.
    pub fn take_all(&mut self) -> Records {
        match &mut self.output {
            Output::Flows(cache) => Records::Flows(cache.export_all()),
            Output::Packets { pending, .. } => Records::Packets(std::mem::take(pending)),
        }
    }

    pub fn active_flows(&self) -> usize {
        match &self.output {
            Output::Flows(cache) => cache.len(),
            Output::Packets { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: ExportArgs,
    }

    /// A meter for an exporter sending from `source` to the collector the
    /// flags name.
    fn meter_from(source: &str, flags: &[&str]) -> Meter {
        let cli = Cli::parse_from([&["export"], flags].concat());
        let collector = cli.args.collector_addr().unwrap();
        Meter::new(
            &cli.args,
            Link::Ethernet,
            source.parse().unwrap(),
            collector,
        )
    }

    fn meter(flags: &[&str]) -> Meter {
        meter_from("10.0.0.9:9", flags)
    }

    /// Ethernet + IPv4 + UDP, 10.0.0.1:1111 -> 10.0.0.2:2222, no payload.
    fn udp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&1111u16.to_be_bytes());
        frame.extend_from_slice(&2222u16.to_be_bytes());
        frame.extend_from_slice(&[0, 8, 0, 0]);
        frame
    }

    fn observe(meter: &mut Meter, data: &[u8], times: usize) {
        for _ in 0..times {
            meter.observe(&Frame { data, length: 1500 });
        }
    }

    #[test]
    fn flow_mode_aggregates_sampled_packets() {
        let mut meter = meter(&["--sampling-packet-interval", "2"]);
        observe(&mut meter, &udp_frame(), 10);

        assert!(!meter.is_full());
        assert_eq!(meter.active_flows(), 1);
        let Records::Flows(flows) = meter.take_all() else {
            panic!("flow mode yields flows");
        };
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packet_count, 5);
        assert_eq!(flows[0].octet_count, 5 * 28);
        assert_eq!(flows[0].key.destination_port, 2222);
    }

    #[test]
    fn packet_mode_clips_every_sampled_frame() {
        let mut meter = meter(&[
            "--mode",
            "packet",
            "--clip-length",
            "20",
            "--sampling-packet-interval",
            "2",
        ]);
        let frame = udp_frame();
        observe(&mut meter, &frame, 10);

        let Records::Packets(packets) = meter.take_due() else {
            panic!("packet mode yields packets");
        };
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].section, frame[..20]);
        assert_eq!(packets[0].length, 1500);
        assert!(matches!(meter.take_due(), Records::Packets(packets) if packets.is_empty()));
    }

    #[test]
    fn own_export_datagrams_are_not_metered() {
        for mode in ["flow", "packet"] {
            let mut meter = meter_from(
                "10.0.0.1:1111",
                &["--mode", mode, "-H", "10.0.0.2", "-p", "2222"],
            );
            observe(&mut meter, &udp_frame(), 10);

            match meter.take_all() {
                Records::Flows(flows) => assert!(flows.is_empty()),
                Records::Packets(packets) => assert!(packets.is_empty()),
            }
        }
    }

    #[test]
    fn another_sender_to_the_collector_is_metered() {
        for mode in ["flow", "packet"] {
            let mut meter = meter_from(
                "10.0.0.1:3333",
                &["--mode", mode, "-H", "10.0.0.2", "-p", "2222"],
            );
            observe(&mut meter, &udp_frame(), 10);

            match meter.take_all() {
                Records::Flows(flows) => assert_eq!(flows[0].packet_count, 10),
                Records::Packets(packets) => assert_eq!(packets.len(), 10),
            }
        }
    }

    #[test]
    fn packet_mode_fills_up() {
        let mut meter = meter(&["--mode", "packet"]);
        observe(&mut meter, &udp_frame(), PACKET_BATCH - 1);
        assert!(!meter.is_full());
        observe(&mut meter, &udp_frame(), 1);
        assert!(meter.is_full());
    }
}
