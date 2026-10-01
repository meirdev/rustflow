// Manual AF_PACKET implementation with PACKET_MMAP (TPACKET_V3).
// We don't use the `af_packet` crate because it has a musl compilation bug:
// ioctl request type mismatch (u64 vs i32) that prevents cross-compilation.
//
// TPACKET_V3 is block-oriented: the kernel packs frames into a block and
// hands over the whole block, so reading costs a wakeup per block instead
// of one per frame.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{io, mem, ptr, slice};

use anyhow::{Result, anyhow};
use log::info;

use super::{Capture, Frame, Link};

const TPACKET_V3: libc::c_int = 2;

const BLOCK_SIZE: u32 = 1 << 16;
const BLOCK_NR: u32 = 64;
const FRAME_SIZE: u32 = 2048;
const FRAME_NR: u32 = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;

/// A block that is not full is handed over after this long, so packets on
/// a quiet link are not held back.
const BLOCK_TIMEOUT_MS: u32 = 100;

/// Bytes of each frame copied into the ring: the headers are all that is
/// parsed, and a V3 frame is otherwise as large as the packet.
const SNAPLEN: u32 = 2048;

/// Classic BPF `ret k`: accept the packet, truncated to `k` bytes.
const BPF_RET: u16 = 0x06;

pub struct AfPacket {
    socket: OwnedFd,
    ring: Ring,
    block_idx: u32,
    /// Whether a block is held. It is handed back on the read after its
    /// last frame, because that frame is still borrowed by the caller.
    block_held: bool,
    /// Frames still to read in the block held.
    frames_left: u32,
    /// Ring offset of the next frame in that block.
    frame_offset: usize,
}

struct Ring {
    ptr: *mut u8,
    len: usize,
}

impl Ring {
    fn map(socket: &OwnedFd, len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                socket.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            len,
        })
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

fn set_option<T>(
    socket: &OwnedFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            ptr::from_ref(value).cast(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AfPacket {
    pub fn new(interface: &str, promiscuous: bool) -> Result<Self> {
        info!("Opening AF_PACKET capture on interface: {}", interface);

        let protocol = (libc::ETH_P_ALL as u16).to_be();
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol as libc::c_int) };
        if fd < 0 {
            return Err(anyhow!(
                "Failed to create socket: {}",
                io::Error::last_os_error()
            ));
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        set_option(&socket, libc::SOL_PACKET, libc::PACKET_VERSION, &TPACKET_V3)
            .map_err(|e| anyhow!("Failed to set TPACKET_V3: {}", e))?;

        let mut snap = libc::sock_filter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SNAPLEN,
        };
        let filter = libc::sock_fprog {
            len: 1,
            filter: &mut snap,
        };
        set_option(&socket, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &filter)
            .map_err(|e| anyhow!("Failed to set the snap length: {}", e))?;

        let req = libc::tpacket_req3 {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_NR,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: FRAME_NR,
            tp_retire_blk_tov: BLOCK_TIMEOUT_MS,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        set_option(&socket, libc::SOL_PACKET, libc::PACKET_RX_RING, &req)
            .map_err(|e| anyhow!("Failed to setup ring buffer: {}", e))?;

        let ring = Ring::map(&socket, (BLOCK_SIZE * BLOCK_NR) as usize)
            .map_err(|e| anyhow!("Failed to mmap ring buffer: {}", e))?;

        let ifindex = get_interface_index(&socket, interface)?;

        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol,
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                ptr::from_ref(&addr).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(anyhow!(
                "Failed to bind to interface: {}",
                io::Error::last_os_error()
            ));
        }

        if promiscuous {
            let mreq = libc::packet_mreq {
                mr_ifindex: ifindex,
                mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            set_option(
                &socket,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to enable promiscuous mode on '{}': {}",
                    interface,
                    e
                )
            })?;

            info!("Promiscuous mode enabled on {}", interface);
        }

        info!(
            "AF_PACKET ring buffer ready: {} blocks of {} KiB",
            BLOCK_NR,
            BLOCK_SIZE / 1024
        );

        Ok(Self {
            socket,
            ring,
            block_idx: 0,
            block_held: false,
            frames_left: 0,
            frame_offset: 0,
        })
    }

    fn block_offset(&self) -> usize {
        (self.block_idx * BLOCK_SIZE) as usize
    }

    fn block(&self) -> *mut libc::tpacket_hdr_v1 {
        unsafe {
            let desc = self.ring.ptr.add(self.block_offset()) as *mut libc::tpacket_block_desc;
            ptr::addr_of_mut!((*desc).hdr.bh1)
        }
    }

    /// The kernel and this thread pass the block back and forth through
    /// its status word.
    fn block_status(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(ptr::addr_of_mut!((*self.block()).block_status)) }
    }

    fn block_ready(&self) -> bool {
        self.block_status().load(Ordering::Acquire) & libc::TP_STATUS_USER != 0
    }

    /// Takes the next block once the kernel has handed it over, waiting up
    /// to a second for it.
    fn acquire_block(&mut self) -> bool {
        if !self.block_ready() {
            let mut pfd = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ret <= 0 || !self.block_ready() {
                return false;
            }
        }

        let (frames, first_frame) = unsafe {
            let block = self.block();
            ((*block).num_pkts, (*block).offset_to_first_pkt)
        };
        self.block_held = true;
        if frames == 0 {
            // Handed over empty by the block timeout.
            self.release_block();
            return false;
        }

        self.frames_left = frames;
        self.frame_offset = self.block_offset() + first_frame as usize;
        true
    }

    fn release_block(&mut self) {
        self.block_status()
            .store(libc::TP_STATUS_KERNEL, Ordering::Release);
        self.block_idx = (self.block_idx + 1) % BLOCK_NR;
        self.block_held = false;
    }
}

impl Capture for AfPacket {
    fn link(&self) -> Link {
        Link::Ethernet
    }

    fn next_frame(&mut self) -> Option<Frame<'_>> {
        if self.frames_left == 0 {
            if self.block_held {
                self.release_block();
            }
            if !self.acquire_block() {
                return None;
            }
        }

        let frame = unsafe { self.ring.ptr.add(self.frame_offset) };
        let hdr = unsafe { &*(frame as *const libc::tpacket3_hdr) };
        let data = unsafe {
            slice::from_raw_parts(frame.add(hdr.tp_mac as usize), hdr.tp_snaplen as usize)
        };

        self.frames_left -= 1;
        self.frame_offset += hdr.tp_next_offset as usize;

        Some(Frame {
            data,
            length: hdr.tp_len,
        })
    }
}

fn get_interface_index(socket: &OwnedFd, interface: &str) -> Result<libc::c_int> {
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

    let ret = unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut ifr) };
    if ret < 0 {
        return Err(anyhow!(
            "Interface '{}' not found: {}",
            interface,
            io::Error::last_os_error()
        ));
    }

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}
