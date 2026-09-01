//! High-throughput UDP relay with optional exporter source preservation.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{io, thread};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};
use tiny_http::{Header, Response, Server};

#[derive(ClapArgs, Debug)]
pub struct RelayArgs {
    /// UDP address on which exporter datagrams are received
    #[arg(long)]
    listen: SocketAddr,

    /// Collector UDP address to which datagrams are forwarded
    #[arg(long)]
    target: SocketAddr,

    /// Forward datagrams from each exporter's original IP address and port
    /// (non-local addresses require Linux and CAP_NET_RAW)
    #[arg(long, short = 's')]
    preserve_source: bool,

    /// Prometheus metrics HTTP bind address
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_listen: SocketAddr,

    /// UDP socket receive/send buffer size in bytes
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    socket_buffer: usize,
}

/// Cached counters for one relay socket, so the hot path never allocates label
/// strings.
struct SocketStats {
    packets: IntCounter,
    bytes: IntCounter,
    drops: IntCounter,
    errors: IntCounter,
}

struct Metrics {
    registry: Registry,
    packets_total: IntCounterVec,
    bytes_total: IntCounterVec,
    dropped_packets_total: IntCounterVec,
    socket_errors_total: IntCounterVec,
    target: String,
    receive: SocketStats,
}

impl Metrics {
    fn new(listen: SocketAddr, target: SocketAddr) -> Result<Self> {
        let registry = Registry::new();
        const LABELS: &[&str] = &["direction", "socket", "target"];

        let packets_total = IntCounterVec::new(
            Opts::new(
                "rustflow_relay_packets_total",
                "UDP datagrams handled by a relay socket",
            ),
            LABELS,
        )?;
        let bytes_total = IntCounterVec::new(
            Opts::new(
                "rustflow_relay_bytes_total",
                "UDP payload bytes handled by a relay socket",
            ),
            LABELS,
        )?;
        let dropped_packets_total = IntCounterVec::new(
            Opts::new(
                "rustflow_relay_dropped_packets_total",
                "UDP datagrams dropped by the relay",
            ),
            LABELS,
        )?;
        let socket_errors_total = IntCounterVec::new(
            Opts::new(
                "rustflow_relay_socket_errors_total",
                "UDP socket operation errors",
            ),
            LABELS,
        )?;

        registry.register(Box::new(packets_total.clone()))?;
        registry.register(Box::new(bytes_total.clone()))?;
        registry.register(Box::new(dropped_packets_total.clone()))?;
        registry.register(Box::new(socket_errors_total.clone()))?;

        let target = target.to_string();
        let receive = socket_stats(
            &packets_total,
            &bytes_total,
            &dropped_packets_total,
            &socket_errors_total,
            "receive",
            listen,
            &target,
        );
        Ok(Metrics {
            registry,
            packets_total,
            bytes_total,
            dropped_packets_total,
            socket_errors_total,
            target,
            receive,
        })
    }

    fn output(&self, source: SocketAddr) -> SocketStats {
        socket_stats(
            &self.packets_total,
            &self.bytes_total,
            &self.dropped_packets_total,
            &self.socket_errors_total,
            "send",
            source,
            &self.target,
        )
    }

    fn encode(&self) -> String {
        let mut buffer = Vec::new();
        let _ = TextEncoder::new().encode(&self.registry.gather(), &mut buffer);
        String::from_utf8(buffer).unwrap_or_default()
    }
}

fn socket_stats(
    packets: &IntCounterVec,
    bytes: &IntCounterVec,
    drops: &IntCounterVec,
    errors: &IntCounterVec,
    direction: &str,
    socket: SocketAddr,
    target: &str,
) -> SocketStats {
    let socket = socket.to_string();
    let labels = &[direction, socket.as_str(), target];
    SocketStats {
        packets: packets.with_label_values(labels),
        bytes: bytes.with_label_values(labels),
        drops: drops.with_label_values(labels),
        errors: errors.with_label_values(labels),
    }
}

struct OutputSocket {
    socket: UdpSocket,
    stats: SocketStats,
}

pub fn run(args: RelayArgs) -> Result<()> {
    if args.listen.is_ipv4() != args.target.is_ipv4() {
        bail!("--listen and --target must use the same address family");
    }
    if args.preserve_source {
        check_preserve_source_support(args.listen.is_ipv4())?;
    }
    let running = Arc::new(AtomicBool::new(true));
    let signal_flag = Arc::clone(&running);
    ctrlc::set_handler(move || signal_flag.store(false, Ordering::Relaxed))?;

    let receive = UdpSocket::bind(args.listen)
        .with_context(|| format!("failed to bind relay listener {}", args.listen))?;
    set_socket_buffer(&receive, libc::SO_RCVBUF, args.socket_buffer)?;
    receive.set_read_timeout(Some(Duration::from_secs(1)))?;

    let metrics = Arc::new(Metrics::new(args.listen, args.target)?);
    start_metrics_server(Arc::clone(&metrics), args.metrics_listen)?;
    let mut outputs: HashMap<SocketAddr, OutputSocket> = HashMap::new();
    let mut shared_output = if args.preserve_source {
        None
    } else {
        Some(create_output(
            None,
            args.target,
            args.socket_buffer,
            &metrics,
        )?)
    };
    let mut buffer = vec![0_u8; 65_535];

    while running.load(Ordering::Relaxed) {
        let (len, source) = match receive.recv_from(&mut buffer) {
            Ok(packet) => packet,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => {
                metrics.receive.errors.inc();
                eprintln!("relay receive error: {error}");
                continue;
            }
        };
        metrics.receive.packets.inc();
        metrics.receive.bytes.inc_by(len as u64);
        let output = if let Some(output) = shared_output.as_mut() {
            output
        } else {
            if let std::collections::hash_map::Entry::Vacant(entry) = outputs.entry(source) {
                match create_output(Some(source), args.target, args.socket_buffer, &metrics) {
                    Ok(output) => {
                        entry.insert(output);
                    }
                    Err(error) => {
                        let stats = metrics.output(source);
                        stats.errors.inc();
                        stats.drops.inc();
                        eprintln!("cannot create output socket for {source}: {error:#}");
                        continue;
                    }
                }
            }
            outputs.get_mut(&source).unwrap()
        };
        match output.socket.send(&buffer[..len]) {
            Ok(sent) if sent == len => {
                output.stats.packets.inc();
                output.stats.bytes.inc_by(sent as u64);
            }
            Ok(_) => {
                output.stats.drops.inc();
            }
            Err(_) => {
                output.stats.errors.inc();
                output.stats.drops.inc();
            }
        }
    }
    Ok(())
}

fn create_output(
    source: Option<SocketAddr>,
    target: SocketAddr,
    buffer_size: usize,
    metrics: &Metrics,
) -> Result<OutputSocket> {
    let bind = source.unwrap_or_else(|| {
        if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        }
    });
    let socket = create_udp_socket(bind, source.is_some() && cfg!(target_os = "linux"))?;
    set_socket_buffer(&socket, libc::SO_SNDBUF, buffer_size)?;
    socket
        .connect(target)
        .with_context(|| format!("failed to connect output socket to {target}"))?;
    let stats = metrics.output(
        socket
            .local_addr()
            .context("reading output socket address")?,
    );
    Ok(OutputSocket { socket, stats })
}

/// Verify at startup that source preservation can work, instead of failing on
/// every datagram later. On Linux this probes the IP_TRANSPARENT socket option,
/// which needs CAP_NET_RAW; elsewhere only locally assigned exporter addresses
/// can be bound, so there is nothing to probe.
#[cfg(target_os = "linux")]
fn check_preserve_source_support(ipv4: bool) -> Result<()> {
    let bind: SocketAddr = if ipv4 { "127.0.0.1:0" } else { "[::1]:0" }
        .parse()
        .unwrap();
    create_udp_socket(bind, true).context(
        "--preserve-source needs transparent sockets \
         (grant CAP_NET_RAW, e.g. `setcap cap_net_raw=ep` on the binary)",
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_preserve_source_support(_ipv4: bool) -> Result<()> {
    eprintln!(
        "warning: --preserve-source can only bind exporter addresses assigned to this host; \
         non-local addresses require Linux"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_udp_socket(bind: SocketAddr, transparent: bool) -> Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    let domain = if bind.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
    if transparent {
        let enabled: libc::c_int = 1;
        let option = if bind.is_ipv4() {
            libc::IP_TRANSPARENT
        } else {
            libc::IPV6_TRANSPARENT
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                if bind.is_ipv4() {
                    libc::SOL_IP
                } else {
                    libc::SOL_IPV6
                },
                option,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .context("enabling transparent UDP (CAP_NET_RAW is normally required)");
        }
    }
    socket
        .bind(&bind.into())
        .with_context(|| format!("failed to bind output socket to {bind}"))?;
    Ok(socket.into())
}

#[cfg(not(target_os = "linux"))]
fn create_udp_socket(bind: SocketAddr, transparent: bool) -> Result<UdpSocket> {
    if transparent {
        bail!("transparent sockets are only supported on Linux");
    }
    UdpSocket::bind(bind).with_context(|| format!("failed to bind output socket to {bind}"))
}

fn set_socket_buffer(socket: &UdpSocket, option: libc::c_int, size: usize) -> Result<()> {
    use std::os::fd::AsRawFd;
    let size = libc::c_int::try_from(size).context("socket buffer size is too large")?;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("setting UDP socket buffer size")
    }
}

fn start_metrics_server(metrics: Arc<Metrics>, address: SocketAddr) -> Result<()> {
    let server = Server::http(address)
        .map_err(|error| anyhow::anyhow!("failed to bind metrics server {address}: {error}"))?;
    thread::Builder::new()
        .name("relay-metrics".into())
        .spawn(move || {
            for request in server.incoming_requests() {
                let response = if request.url() == "/metrics" {
                    Response::from_string(metrics.encode()).with_header(
                        Header::from_bytes("Content-Type", "text/plain; version=0.0.4").unwrap(),
                    )
                } else {
                    Response::from_string("not found\n").with_status_code(404)
                };
                let _ = request.respond(response);
            }
        })?;
    Ok(())
}
