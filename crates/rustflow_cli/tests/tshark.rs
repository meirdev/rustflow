//! What `rustflow generate` writes, as Wireshark reads it: a capture per
//! protocol, decoded with `tshark` and checked field by field. Skipped,
//! with a note, where `tshark` is not installed.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const PACKETS: usize = 4;
const FLOWS_PER_PACKET: usize = 3;
/// Ports for sFlow's sampled packets, above the well-known ones: on those,
/// Wireshark dissects the sampled packet's zero payload as the port's
/// protocol and finds it malformed where the header was cut.
const HIGH_PORTS: &[&str] = &[
    "--src-port-range",
    "30000-39999",
    "--dst-port-range",
    "40000-49999",
];

/// The fields of every packet of `path` as `tshark` decodes them: for each
/// packet, for each field asked for, its occurrences.
fn decoded(path: &Path, fields: &[&str]) -> Vec<Vec<Vec<String>>> {
    let mut tshark = Command::new("tshark");
    tshark
        .arg("-r")
        .arg(path)
        .args(["-T", "fields", "-E", "separator=|"]);
    for field in fields {
        tshark.args(["-e", field]);
    }
    let output = tshark.output().expect("tshark runs");
    assert!(
        output.status.success(),
        "tshark: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8")
        .lines()
        .map(|line| {
            line.split('|')
                .map(|field| {
                    field
                        .split(',')
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// The packets `tshark` finds malformed or warns about.
fn problems(path: &Path) -> String {
    let output = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(["-Y", "_ws.malformed || _ws.expert.severity >= warning"])
        .output()
        .expect("tshark runs");
    assert!(
        output.status.success(),
        "tshark: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Generates a capture of `protocol` to the port Wireshark decodes it on.
fn generate(protocol: &str, port: u16, args: &[&str]) -> PathBuf {
    static CAPTURES: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "rustflow-tshark-{}-{}-{protocol}.pcap",
        std::process::id(),
        CAPTURES.fetch_add(1, Ordering::Relaxed)
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_rustflow"))
        .args(["generate", "--protocol", protocol, "--rate", "0"])
        .args(["--count", &PACKETS.to_string()])
        .args(["--flows-per-packet", &FLOWS_PER_PACKET.to_string()])
        .args(["--port", &port.to_string()])
        .arg("--output")
        .arg(&path)
        .args(args)
        .status()
        .expect("rustflow runs");
    assert!(status.success(), "rustflow generate {protocol}");
    path
}

fn tshark_installed() -> bool {
    let installed = Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !installed {
        eprintln!("tshark is not installed; skipping");
    }
    installed
}

fn in_ten_slash_eight(address: &str) -> bool {
    address
        .parse::<Ipv4Addr>()
        .is_ok_and(|address| address.octets()[0] == 10)
}

#[test]
fn netflow_v5_decodes_in_wireshark() {
    if !tshark_installed() {
        return;
    }
    let path = generate("netflow-v5", 2055, &[]);
    assert_eq!(problems(&path), "");
    let packets = decoded(
        &path,
        &[
            "cflow.version",
            "cflow.count",
            "cflow.sequence",
            "cflow.srcaddr",
            "cflow.octets",
            "cflow.timestart",
        ],
    );
    assert_eq!(packets.len(), PACKETS);
    for (i, packet) in packets.iter().enumerate() {
        let [version, count, sequence, sources, octets, starts] = &packet[..] else {
            panic!("{packet:?}");
        };
        assert_eq!(version, &["5"]);
        assert_eq!(count, &[FLOWS_PER_PACKET.to_string()]);
        assert_eq!(sequence, &[(i * FLOWS_PER_PACKET).to_string()]);
        assert_eq!(sources.len(), FLOWS_PER_PACKET);
        assert!(sources.iter().all(|s| in_ten_slash_eight(s)), "{sources:?}");
        assert_eq!(octets.len(), FLOWS_PER_PACKET);
        assert_eq!(starts.len(), FLOWS_PER_PACKET);
    }
    std::fs::remove_file(path).unwrap();
}

/// NetFlow v9 and IPFIX alike: the first packet carries a data template,
/// an options template and the sampling options, every packet the flows.
fn templated_decodes(protocol: &str, version: &str, start_field: &str) {
    let path = generate(protocol, 4739, &[]);
    assert_eq!(problems(&path), "");
    let packets = decoded(
        &path,
        &[
            "cflow.version",
            "cflow.template_id",
            "cflow.sampling_packet_interval",
            "cflow.srcaddr",
            "cflow.srcport",
            start_field,
        ],
    );
    assert_eq!(packets.len(), PACKETS);
    for (i, packet) in packets.iter().enumerate() {
        let [versions, templates, sampling, sources, ports, starts] = &packet[..] else {
            panic!("{packet:?}");
        };
        assert_eq!(versions, &[version]);
        if i == 0 {
            let mut templates = templates.clone();
            templates.sort();
            assert_eq!(templates, ["256", "257"]);
            assert_eq!(sampling, &["1"]);
        } else {
            assert!(templates.is_empty(), "templates sent again: {templates:?}");
            assert!(sampling.is_empty());
        }
        assert_eq!(sources.len(), FLOWS_PER_PACKET);
        assert!(sources.iter().all(|s| in_ten_slash_eight(s)), "{sources:?}");
        assert_eq!(ports.len(), FLOWS_PER_PACKET);
        assert_eq!(starts.len(), FLOWS_PER_PACKET);
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn netflow_v9_decodes_in_wireshark() {
    if !tshark_installed() {
        return;
    }
    templated_decodes("netflow-v9", "9", "cflow.timestart");
}

#[test]
fn ipfix_decodes_in_wireshark() {
    if !tshark_installed() {
        return;
    }
    templated_decodes("ipfix", "10", "cflow.abstimestart");
}

#[test]
fn sflow_decodes_in_wireshark() {
    if !tshark_installed() {
        return;
    }
    let path = generate("sflow", 6343, &[&["--protocols", "6"], HIGH_PORTS].concat());
    assert_eq!(problems(&path), "");
    let packets = decoded(
        &path,
        &[
            "sflow_245.agent",
            "sflow_245.sub_agent_id",
            "sflow_245.numsamples",
            "sflow.flow_sample.sampling_rate",
            "sflow_245.header.frame_length",
            "ip.src",
            "tcp.srcport",
        ],
    );
    assert_eq!(packets.len(), PACKETS);
    for packet in &packets {
        let [agent, sub_agent, samples, rates, lengths, sources, ports] = &packet[..] else {
            panic!("{packet:?}");
        };
        assert_eq!(agent, &["192.0.2.1"]);
        assert_eq!(sub_agent, &["1"]);
        assert_eq!(samples, &[FLOWS_PER_PACKET.to_string()]);
        assert_eq!(rates, &["1"; FLOWS_PER_PACKET]);
        assert_eq!(lengths.len(), FLOWS_PER_PACKET);
        // The datagram's own source, then the sampled packets'.
        assert_eq!(sources[0], "192.0.2.1");
        assert_eq!(sources.len(), 1 + FLOWS_PER_PACKET);
        assert!(
            sources[1..].iter().all(|s| in_ten_slash_eight(s)),
            "{sources:?}"
        );
        assert_eq!(ports.len(), FLOWS_PER_PACKET, "every sampled TCP header");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn ipv6_flows_decode_in_wireshark() {
    if !tshark_installed() {
        return;
    }
    let ranges = [
        "--src-cidr",
        "2001:db8:1::/48",
        "--dst-cidr",
        "2001:db8:2::/48",
    ];
    let path = generate("ipfix", 4739, &ranges);
    assert_eq!(problems(&path), "");
    let packets = decoded(&path, &["cflow.srcaddrv6"]);
    assert!(packets.iter().all(|p| p[0].len() == FLOWS_PER_PACKET));
    std::fs::remove_file(path).unwrap();

    let path = generate("sflow", 6343, &[&ranges, HIGH_PORTS].concat());
    assert_eq!(problems(&path), "");
    let packets = decoded(&path, &["sflow_245.agent.v6", "ipv6.src"]);
    assert!(packets.iter().all(|p| p[0] == ["2001:db8::1"]));
    assert!(packets.iter().all(|p| p[1].len() == FLOWS_PER_PACKET));
    std::fs::remove_file(path).unwrap();
}
