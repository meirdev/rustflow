// Manual AF_PACKET implementation with PACKET_MMAP (TPACKET_V3).
// We don't use the `af_packet` crate because it has a musl compilation bug:
// ioctl request type mismatch (u64 vs i32) that prevents cross-compilation.
//
// TPACKET_V3 is block-oriented: the kernel packs variable-sized frames into
// fixed-size blocks and hands userspace a whole block at once, which costs
// far fewer wakeups than the per-frame TPACKET_V2 ring under load. A
// partially filled block is retired after `RETIRE_TOV_MS` so packets are not
// delayed on quiet links.

use std::ffi::CString;
use std::sync::atomic::{Ordering, fence};
use std::{io, mem, ptr};

use anyhow::{Result, anyhow};
use log::info;

use super::{CaptureBackend, CaptureConfig, CaptureStats, PacketInfo, Sampler, parse_ethernet};

// AF_PACKET constants
const ETH_P_ALL: u16 = 0x0003;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_VERSION: libc::c_int = 10;
const TPACKET_V3: libc::c_int = 2;
const PACKET_MR_PROMISC: libc::c_ushort = 1;

// Ring buffer configuration: 64 blocks of 64 KiB (4 MiB total). The frame
// size only shapes the tp_frame_nr bookkeeping in TPACKET_V3; frames in a
// block are variable-sized.
const BLOCK_SIZE: u32 = 1 << 16;
const BLOCK_NR: u32 = 64;
const FRAME_SIZE: u32 = 2048;
const FRAME_NR: u32 = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;

/// Kernel retires a partially filled block after this many milliseconds.
const RETIRE_TOV_MS: u32 = 100;

// Block status flags
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;

#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [libc::c_uchar; 8],
}

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
    tp_retire_blk_tov: libc::c_uint,
    tp_sizeof_priv: libc::c_uint,
    tp_feature_req_word: libc::c_uint,
}

#[repr(C)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_usec: u32,
}

/// `struct tpacket_hdr_v1`: the header at the start of every ready block.
#[repr(C)]
struct TpacketHdrV1 {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

/// `struct tpacket_block_desc`.
#[repr(C)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketHdrV1,
}

/// `struct tpacket3_hdr`: precedes every frame inside a block.
#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    hv1_rxhash: u32,
    hv1_vlan_tci: u32,
    hv1_vlan_tpid: u16,
    hv1_padding: u16,
    tp_padding: [u8; 8],
}

pub struct AfPacketCapture {
    fd: libc::c_int,
    ring: *mut u8,
    ring_size: usize,
    block_idx: u32,
    /// Packets left to consume in the currently owned block; 0 means no
    /// block is owned.
    pkts_remaining: u32,
    /// Ring offset of the next `Tpacket3Hdr` in the owned block.
    next_pkt_offset: usize,
    sampler: Sampler,
    section_length: Option<usize>,
}

impl AfPacketCapture {
    pub fn new(interface: &str, config: &CaptureConfig) -> Result<Self> {
        let promiscuous = config.promiscuous;
        info!("Opening AF_PACKET capture on interface: {}", interface);

        // Create AF_PACKET socket
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                ETH_P_ALL.to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "Failed to create socket: {}",
                io::Error::last_os_error()
            ));
        }

        // Set TPACKET_V3
        let version: libc::c_int = TPACKET_V3;
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
                "Failed to set TPACKET_V3: {}",
                io::Error::last_os_error()
            ));
        }

        // Setup ring buffer
        let req = TpacketReq3 {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_NR,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: FRAME_NR,
            tp_retire_blk_tov: RETIRE_TOV_MS,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                mem::size_of::<TpacketReq3>() as libc::socklen_t,
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
            sll_protocol: ETH_P_ALL.to_be(),
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

        if promiscuous {
            let mreq = PacketMreq {
                mr_ifindex: ifindex,
                mr_type: PACKET_MR_PROMISC,
                mr_alen: 0,
                mr_address: [0; 8],
            };

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mreq as *const _ as *const libc::c_void,
                    mem::size_of::<PacketMreq>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                unsafe {
                    libc::munmap(ring, ring_size);
                    libc::close(fd);
                }
                return Err(anyhow!(
                    "Failed to enable promiscuous mode on '{}': {}",
                    interface,
                    io::Error::last_os_error()
                ));
            }

            info!("Promiscuous mode enabled on {}", interface);
        }

        info!(
            "AF_PACKET TPACKET_V3 ring ready: {} blocks of {} KiB",
            BLOCK_NR,
            BLOCK_SIZE / 1024
        );

        Ok(Self {
            fd,
            ring: ring as *mut u8,
            ring_size,
            block_idx: 0,
            pkts_remaining: 0,
            next_pkt_offset: 0,
            sampler: Sampler::new(config.sampling),
            section_length: config.section_length,
        })
    }

    fn block_desc(&self) -> *mut TpacketBlockDesc {
        let offset = (self.block_idx * BLOCK_SIZE) as usize;
        unsafe { self.ring.add(offset) as *mut TpacketBlockDesc }
    }

    /// Try to take ownership of the current block. Waits up to a second for
    /// the kernel to hand one over.
    fn acquire_block(&mut self) -> bool {
        let status = unsafe { ptr::read_volatile(&(*self.block_desc()).hdr.block_status) };
        if status & TP_STATUS_USER == 0 {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) }; // 1 second timeout
            if ret <= 0 {
                return false;
            }
            let status = unsafe { ptr::read_volatile(&(*self.block_desc()).hdr.block_status) };
            if status & TP_STATUS_USER == 0 {
                return false;
            }
        }
        // The status read must happen before we read the block's contents.
        fence(Ordering::Acquire);

        let block = unsafe { &*self.block_desc() };
        self.pkts_remaining = block.hdr.num_pkts;
        self.next_pkt_offset =
            (self.block_idx * BLOCK_SIZE) as usize + block.hdr.offset_to_first_pkt as usize;

        if self.pkts_remaining == 0 {
            // Retired empty by the block timeout.
            self.release_block();
            return false;
        }
        true
    }

    /// Hand the current block back to the kernel and move to the next one.
    fn release_block(&mut self) {
        // All reads from the block must happen before the kernel reuses it.
        fence(Ordering::Release);
        unsafe {
            ptr::write_volatile(&mut (*self.block_desc()).hdr.block_status, TP_STATUS_KERNEL);
        }
        self.block_idx = (self.block_idx + 1) % BLOCK_NR;
        self.pkts_remaining = 0;
    }
}

impl CaptureBackend for AfPacketCapture {
    fn next_packet(&mut self) -> Option<PacketInfo> {
        if self.pkts_remaining == 0 && !self.acquire_block() {
            return None;
        }

        let hdr = unsafe { &*(self.ring.add(self.next_pkt_offset) as *const Tpacket3Hdr) };
        let result = if self.sampler.select() {
            let packet_data = unsafe {
                let data_ptr = self.ring.add(self.next_pkt_offset + hdr.tp_mac as usize);
                std::slice::from_raw_parts(data_ptr, hdr.tp_snaplen as usize)
            };
            parse_ethernet(packet_data).map(|mut info| {
                info.frame_length = hdr.tp_len;
                info.observation_time_ms =
                    hdr.tp_sec as i64 * 1_000 + hdr.tp_nsec as i64 / 1_000_000;
                info.section = self
                    .section_length
                    .map(|n| packet_data[..n.min(packet_data.len())].to_vec());
                info
            })
        } else {
            None
        };

        self.pkts_remaining -= 1;
        if self.pkts_remaining == 0 {
            self.release_block();
        } else {
            self.next_pkt_offset += hdr.tp_next_offset as usize;
        }

        result
    }

    fn stats(&self) -> CaptureStats {
        self.sampler.stats()
    }
}

impl Drop for AfPacketCapture {
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
