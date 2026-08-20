// Manual AF_PACKET implementation with PACKET_MMAP (TPACKET_V2).
// We don't use the `af_packet` crate because it has a musl compilation bug:
// ioctl request type mismatch (u64 vs i32) that prevents cross-compilation.

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::{io, mem, ptr};

use anyhow::{Result, anyhow};
use etherparse::{SlicedPacket, TransportSlice};
use log::{debug, info};

use crate::flow::FlowKey;

// AF_PACKET constants
const ETH_P_ALL: u16 = 0x0003;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_VERSION: libc::c_int = 10;
const TPACKET_V2: libc::c_int = 1;

// Ring buffer configuration
const FRAME_SIZE: u32 = 2048;
const BLOCK_SIZE: u32 = 4096;
const BLOCK_NR: u32 = 256;
const FRAME_NR: u32 = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;

// Frame status flags
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;

#[repr(C)]
struct TpacketReq {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
}

#[repr(C)]
struct Tpacket2Hdr {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 4],
}

pub struct PacketCapture {
    fd: libc::c_int,
    ring: *mut u8,
    ring_size: usize,
    frame_idx: u32,
}

impl PacketCapture {
    pub fn new(interface: &str, _promiscuous: bool) -> Result<Self> {
        info!("Opening AF_PACKET capture on interface: {}", interface);

        // Create AF_PACKET socket
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "Failed to create socket: {}",
                io::Error::last_os_error()
            ));
        }

        // Set TPACKET_V2
        let version: libc::c_int = TPACKET_V2;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "Failed to set TPACKET_V2: {}",
                io::Error::last_os_error()
            ));
        }

        // Setup ring buffer
        let req = TpacketReq {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_NR,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: FRAME_NR,
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                mem::size_of::<TpacketReq>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "Failed to setup ring buffer: {}",
                io::Error::last_os_error()
            ));
        }

        // mmap the ring buffer
        let ring_size = (BLOCK_SIZE * BLOCK_NR) as usize;
        let ring = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "Failed to mmap ring buffer: {}",
                io::Error::last_os_error()
            ));
        }

        // Get interface index
        let ifindex = get_interface_index(fd, interface)?;

        // Bind to interface
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe {
                libc::munmap(ring, ring_size);
                libc::close(fd);
            }
            return Err(anyhow!(
                "Failed to bind to interface: {}",
                io::Error::last_os_error()
            ));
        }

        info!("AF_PACKET ring buffer ready: {} frames", FRAME_NR);

        Ok(Self {
            fd,
            ring: ring as *mut u8,
            ring_size,
            frame_idx: 0,
        })
    }

    pub fn next_packet(&mut self) -> Option<PacketInfo> {
        // Poll for packet availability with timeout
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pfd, 1, 1000) }; // 1 second timeout
        if ret <= 0 {
            return None;
        }

        // Check current frame
        let frame_offset = (self.frame_idx * FRAME_SIZE) as usize;
        let hdr = unsafe { &mut *(self.ring.add(frame_offset) as *mut Tpacket2Hdr) };

        if (hdr.tp_status & TP_STATUS_USER) == 0 {
            return None;
        }

        // Get packet data
        let packet_data = unsafe {
            let data_ptr = self.ring.add(frame_offset + hdr.tp_mac as usize);
            std::slice::from_raw_parts(data_ptr, hdr.tp_snaplen as usize)
        };

        let result = parse_packet(packet_data);

        // Return frame to kernel
        hdr.tp_status = TP_STATUS_KERNEL;

        // Move to next frame
        self.frame_idx = (self.frame_idx + 1) % FRAME_NR;

        result
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring as *mut libc::c_void, self.ring_size);
            libc::close(self.fd);
        }
    }
}

fn get_interface_index(fd: libc::c_int, interface: &str) -> Result<libc::c_int> {
    let ifname = CString::new(interface)?;
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

    // Copy interface name (max 15 chars + null)
    let name_bytes = ifname.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
    unsafe {
        ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    // ioctl request type differs between glibc (c_ulong) and musl (c_int)
    #[cfg(target_env = "musl")]
    let request = libc::SIOCGIFINDEX as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let request = libc::SIOCGIFINDEX as libc::c_ulong;

    let ret = unsafe { libc::ioctl(fd, request, &mut ifr) };
    if ret < 0 {
        return Err(anyhow!(
            "Interface '{}' not found: {}",
            interface,
            io::Error::last_os_error()
        ));
    }

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub flow_key: FlowKey,
    pub packet_size: u64,
    pub tcp_flags: u16,
}

fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to parse packet: {:?}", e);
            return None;
        }
    };

    let (source_ip, dest_ip, protocol, total_length) = match sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                Ipv4Addr::from(header.source()),
                Ipv4Addr::from(header.destination()),
                header.protocol().0,
                header.total_len() as u64,
            )
        }
        Some(etherparse::NetSlice::Ipv6(_)) => {
            debug!("Skipping IPv6 packet");
            return None;
        }
        None => {
            debug!("No IP layer found");
            return None;
        }
    };

    let (source_port, dest_port, tcp_flags) = match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let header = tcp.to_header();
            let flags = (header.ns as u16) << 8
                | (header.fin as u16)
                | ((header.syn as u16) << 1)
                | ((header.rst as u16) << 2)
                | ((header.psh as u16) << 3)
                | ((header.ack as u16) << 4)
                | ((header.urg as u16) << 5)
                | ((header.ece as u16) << 6)
                | ((header.cwr as u16) << 7);
            (header.source_port, header.destination_port, flags)
        }
        Some(TransportSlice::Udp(udp)) => {
            let header = udp.to_header();
            (header.source_port, header.destination_port, 0)
        }
        _ => (0, 0, 0),
    };

    Some(PacketInfo {
        flow_key: FlowKey {
            source_ip,
            destination_ip: dest_ip,
            protocol,
            source_port,
            destination_port: dest_port,
        },
        packet_size: total_length,
        tcp_flags,
    })
}
