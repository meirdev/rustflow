//! A deliberately minimal collector, used to find which layer of the ingest
//! path costs what.
//!
//! The full `rustflow collect` does receive, parse, convert, enrich, channel
//! handoff, encode and write, so a drop rate measured against it cannot say
//! which of those is responsible. This runs the same traffic through
//! progressively more of the stack and reports the throughput of each, so the
//! expensive layer is the one where the number falls off:
//!
//!   recv     recv_from into a scratch buffer, count bytes, discard
//!   parse    + NetflowProcessor::parse_raw   (decode to NetflowPacket)
//!   convert  + convert_to_flows              (build CommonFlow records)
//!
//! With a thread count above 1 it opens that many `SO_REUSEPORT` sockets on
//! the same port, one receive loop each, to measure how the decode path scales
//! across cores.
//!
//!   min_collector <recv|parse|convert> [bind_addr] [threads]
//!
//!   cargo run --release --example min_collector -- convert 0.0.0.0:4739 4
//!
//! **`SO_REUSEPORT` distributes by connection hash, not round-robin.** The
//! kernel picks a socket from the packet's 4-tuple, so every datagram from one
//! exporter address+port lands on the *same* socket. Traffic from many
//! exporters spreads across threads; traffic from a single exporter does not
//! spread at all, and the extra threads sit idle. The per-thread packet counts
//! printed at exit show what actually happened.
//!
//! Each thread keeps its own template cache, which is only sound because of
//! that same property: a given exporter is always served by one thread, so its
//! templates are always where its data records are.
//!
//! Set RECV_BUFFER=16777216 to request a larger socket buffer per socket (the
//! kernel clamps to net.core.rmem_max). Ctrl-C prints the totals.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustflow_lib::NetflowProcessor;

/// Cleared by SIGINT/SIGTERM so a run can be stopped and still print totals.
static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Recv,
    Parse,
    Convert,
}

#[derive(Default)]
struct Counters {
    packets: AtomicU64,
    flows: AtomicU64,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("recv") => Mode::Recv,
        Some("parse") => Mode::Parse,
        Some("convert") => Mode::Convert,
        other => {
            eprintln!("usage: min_collector <recv|parse|convert> [bind_addr] [threads]");
            eprintln!("  got: {:?}", other);
            std::process::exit(2);
        }
    };
    let addr: SocketAddr = args
        .next()
        .unwrap_or_else(|| "0.0.0.0:4739".to_string())
        .parse()
        .expect("bind address");
    let threads: usize = args
        .next()
        .map(|t| t.parse().expect("thread count"))
        .unwrap_or(1)
        .max(1);

    let recv_buffer = std::env::var("RECV_BUFFER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let mut sockets = Vec::with_capacity(threads);
    for _ in 0..threads {
        // One SO_REUSEPORT socket per thread: the kernel then has a set to
        // hash into, rather than one queue every thread contends on.
        let socket = bind_reuseport(addr).expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set_read_timeout");
        if let Some(bytes) = recv_buffer {
            match set_recv_buffer(&socket, bytes) {
                Ok(granted) => {
                    if sockets.is_empty() {
                        eprintln!("recv buffer: requested {bytes}, granted {granted} per socket");
                    }
                }
                Err(e) => eprintln!("recv buffer: failed to set: {e}"),
            }
        }
        sockets.push(socket);
    }

    eprintln!(
        "min_collector [{}] listening on {} with {} thread(s)",
        mode_name(mode),
        addr,
        threads
    );

    install_signal_handler();

    let counters: Vec<Arc<Counters>> = (0..threads)
        .map(|_| Arc::new(Counters::default()))
        .collect();
    let drops_at_start = udp_drops(addr.port()).unwrap_or(0);
    let start = Instant::now();

    // The workers take ownership of their sockets and close them on exit, which
    // removes the rows from /proc/net/udp. Holding a duplicate of each keeps
    // the port bound until the final drop count has been read -- otherwise the
    // counter reads as zero and a saturated run looks lossless.
    let _keep_bound: Vec<UdpSocket> = sockets
        .iter()
        .map(|s| s.try_clone().expect("try_clone"))
        .collect();

    let workers: Vec<_> = sockets
        .into_iter()
        .zip(counters.iter().cloned())
        .map(|(socket, counters)| std::thread::spawn(move || worker(mode, socket, counters)))
        .collect();

    // Progress is reported from here so the workers stay a tight loop.
    let mut last = Instant::now();
    let (mut last_packets, mut last_flows) = (0u64, 0u64);
    while RUNNING.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        let elapsed = last.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            continue;
        }
        let (packets, flows) = totals(&counters);
        eprintln!(
            "  {:>9.0} pkt/s  {:>11.0} flow/s  kernel_drops={}",
            (packets - last_packets) as f64 / elapsed,
            (flows - last_flows) as f64 / elapsed,
            udp_drops(addr.port())
                .unwrap_or(0)
                .saturating_sub(drops_at_start)
        );
        last = Instant::now();
        last_packets = packets;
        last_flows = flows;
    }

    for w in workers {
        let _ = w.join();
    }

    let secs = start.elapsed().as_secs_f64();
    let (packets, flows) = totals(&counters);
    let dropped = udp_drops(addr.port())
        .unwrap_or(0)
        .saturating_sub(drops_at_start);

    println!();
    println!("mode:          {}", mode_name(mode));
    println!("threads:       {threads}");
    println!("duration:      {secs:.2} s");
    println!("packets:       {packets} ({:.0}/s)", packets as f64 / secs);
    if mode == Mode::Convert {
        println!("flows:         {flows} ({:.0}/s)", flows as f64 / secs);
    }
    println!("kernel drops:  {dropped}");
    if packets + dropped > 0 {
        println!(
            "drop rate:     {:.2}%",
            dropped as f64 / (packets + dropped) as f64 * 100.0
        );
    }
    if threads > 1 {
        // Uneven counts mean the 4-tuple hash favoured some sockets; with a
        // single exporter one thread does everything.
        let per: Vec<String> = counters
            .iter()
            .map(|c| c.packets.load(Ordering::Relaxed).to_string())
            .collect();
        println!("per-thread:    {}", per.join(" "));
    }
}

fn totals(counters: &[Arc<Counters>]) -> (u64, u64) {
    counters.iter().fold((0, 0), |(p, f), c| {
        (
            p + c.packets.load(Ordering::Relaxed),
            f + c.flows.load(Ordering::Relaxed),
        )
    })
}

fn worker(mode: Mode, socket: UdpSocket, counters: Arc<Counters>) {
    let mut processor = NetflowProcessor::new();
    let mut buf = vec![0u8; 65535];
    let (mut packets, mut flows) = (0u64, 0u64);

    while RUNNING.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                packets += 1;
                if mode != Mode::Recv {
                    let src = src.ip();
                    if let Some(packet) = processor.parse_raw(src, &buf[..len]) {
                        if mode == Mode::Convert {
                            let converted = processor.convert_to_flows(src, &packet, Some(0));
                            flows += converted.len() as u64;
                        }
                    }
                }
                // Publishing every packet would put an atomic on the hot path;
                // the reporter tolerates counts being a fraction of a second
                // stale.
                if packets % 1024 == 0 {
                    counters.packets.store(packets, Ordering::Relaxed);
                    counters.flows.store(flows, Ordering::Relaxed);
                }
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        }
    }

    counters.packets.store(packets, Ordering::Relaxed);
    counters.flows.store(flows, Ordering::Relaxed);
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Recv => "recv",
        Mode::Parse => "parse",
        Mode::Convert => "convert",
    }
}

/// Bind a UDP socket with `SO_REUSEPORT`, so several can share one port.
///
/// The option has to be set between `socket()` and `bind()`, which
/// `UdpSocket::bind` does in one step, so the socket is built by hand.
#[cfg(target_os = "linux")]
fn bind_reuseport(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Owned from here, so every early return closes it via Drop.
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };

    let on: libc::c_int = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(socket)
}

#[cfg(not(target_os = "linux"))]
fn bind_reuseport(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr)
}

/// Total kernel drop counter across every socket bound to `port`.
///
/// With `SO_REUSEPORT` there is one row per socket and drops are counted per
/// socket, so they have to be summed.
fn udp_drops(port: u16) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/udp").ok()?;
    let want = format!(":{port:04X}");
    let mut total = 0u64;
    let mut found = false;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 || !cols[1].ends_with(&want) {
            continue;
        }
        if let Some(drops) = cols.last().and_then(|d| d.parse::<u64>().ok()) {
            total += drops;
            found = true;
        }
    }
    found.then_some(total)
}

#[cfg(unix)]
fn set_recv_buffer(socket: &UdpSocket, bytes: usize) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let requested = bytes as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &requested as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut actual: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut actual as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        );
    }
    // Linux reports back double what was set.
    Ok(if cfg!(target_os = "linux") {
        actual as usize / 2
    } else {
        actual as usize
    })
}

#[cfg(not(unix))]
fn set_recv_buffer(_socket: &UdpSocket, _bytes: usize) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported on this platform",
    ))
}

/// Minimal SIGINT/SIGTERM handling, so a run can be stopped with Ctrl-C and
/// still print its totals, without pulling a dependency into an example.
#[cfg(unix)]
fn install_signal_handler() {
    extern "C" fn on_signal(_: libc::c_int) {
        RUNNING.store(false, Ordering::Relaxed);
    }
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signal_handler() {}
