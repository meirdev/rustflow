//! Native macOS capture through a BPF device (`/dev/bpfN`), the primitive
//! libpcap itself uses on macOS, so this build needs no library. Each
//! `read` returns a batch of records, every one a `struct bpf_hdr`
//! followed by the captured bytes and padded to `BPF_ALIGNMENT`.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::{io, mem, ptr};

use anyhow::{Context, Result, bail};
use log::info;

use super::packet::{Sampler, parse_ethernet, parse_ip};
use super::{Capture, PacketInfo};

/// Not in the `libc` crate: `_IOW('B', 109, struct timeval)`.
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;

const DLT_NULL: u32 = 0;
const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 12;
const DLT_LOOP: u32 = 108;

/// Records are padded to `sizeof(int32_t)`.
const ALIGNMENT: usize = 4;
/// `bh_caplen` and `bh_hdrlen` inside `struct bpf_hdr`, after the 32-bit
/// timeval. `bh_hdrlen` is read from each record because the kernel sizes
/// it per link type so the IP header lands word-aligned.
const CAPLEN_OFFSET: usize = 8;
const HDRLEN_OFFSET: usize = 16;
const MIN_HEADER_LEN: usize = 18;

/// The kernel caps it at `debug.bpf_maxbufsize`, 512 KiB by default;
/// `BIOCSETIF` fails with `ENOBUFS` above the cap and the size is halved until
/// it fits.
const BUFFER_SIZE: libc::c_uint = 512 * 1024;
const MAX_DEVICES: u32 = 256;

enum LinkLayer {
    Ethernet,
    /// A 4-byte address-family word, then the IP header.
    Loopback,
    RawIp,
}

pub struct Bpf {
    device: File,
    link_layer: LinkLayer,
    buf: Vec<u8>,
    /// Bytes of `buf` filled by the last read, and how far they are consumed.
    len: usize,
    pos: usize,
    sampler: Sampler,
}

impl Bpf {
    pub fn new(interface: &str, promiscuous: bool, sampling_interval: u32) -> Result<Self> {
        info!("Opening BPF capture on interface: {}", interface);
        let device = open_device()?;
        let fd = device.as_raw_fd();

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        let name = CString::new(interface)?;
        let name = name.as_bytes_with_nul();
        if name.len() > libc::IFNAMSIZ {
            bail!("Interface name '{interface}' is too long");
        }
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                name.len(),
            );
        }

        // The buffer must be sized before the interface is attached.
        let mut size = BUFFER_SIZE;
        loop {
            unsafe { libc::ioctl(fd, libc::BIOCSBLEN, &mut size) };
            if unsafe { libc::ioctl(fd, libc::BIOCSETIF, &ifr) } == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOBUFS) && size > 4096 {
                size /= 2;
                continue;
            }
            return Err(err)
                .with_context(|| format!("Failed to attach to interface '{interface}'"));
        }
        let mut size: libc::c_uint = 0;
        ioctl(fd, libc::BIOCGBLEN, &mut size, "read the buffer size")?;

        // Deliver packets as they arrive instead of when the buffer fills,
        // and bound each read so the caller's timers keep running.
        let mut immediate: libc::c_uint = 1;
        ioctl(
            fd,
            libc::BIOCIMMEDIATE,
            &mut immediate,
            "enable immediate mode",
        )?;
        let mut timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        ioctl(fd, BIOCSRTIMEOUT, &mut timeout, "set the read timeout")?;

        if promiscuous {
            if unsafe { libc::ioctl(fd, libc::BIOCPROMISC as libc::c_ulong) } < 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("Failed to enable promiscuous mode on '{interface}'")
                });
            }
            info!("Promiscuous mode enabled on {}", interface);
        }

        let mut dlt: u32 = 0;
        ioctl(fd, libc::BIOCGDLT, &mut dlt, "read the link type")?;
        let link_layer = match dlt {
            DLT_EN10MB => LinkLayer::Ethernet,
            DLT_NULL | DLT_LOOP => LinkLayer::Loopback,
            DLT_RAW => LinkLayer::RawIp,
            other => bail!(
                "Unsupported link type {other} on '{interface}'; only Ethernet, loopback and raw IP are supported"
            ),
        };

        info!("BPF buffer ready: {} bytes", size);
        Ok(Self {
            device,
            link_layer,
            buf: vec![0; size as usize],
            len: 0,
            pos: 0,
            sampler: Sampler::new(sampling_interval),
        })
    }

    /// Reads the next batch; `false` on timeout or error.
    fn fill(&mut self) -> bool {
        self.len = 0;
        self.pos = 0;
        let n = unsafe {
            libc::read(
                self.device.as_raw_fd(),
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
            )
        };
        if n <= 0 {
            return false;
        }
        self.len = n as usize;
        true
    }
}

impl Capture for Bpf {
    fn next_packet(&mut self) -> Option<PacketInfo> {
        loop {
            if self.pos >= self.len && !self.fill() {
                return None;
            }
            let Some((data, next)) = record(&self.buf[..self.len], self.pos) else {
                // A truncated tail: drop the rest of the batch.
                self.len = 0;
                return None;
            };
            self.pos = next;
            if !self.sampler.select() {
                continue;
            }
            return match self.link_layer {
                LinkLayer::Ethernet => parse_ethernet(data),
                LinkLayer::Loopback => parse_ip(data.get(4..)?),
                LinkLayer::RawIp => parse_ip(data),
            };
        }
    }
}

/// The captured bytes of the record at `pos` and the offset of the record
/// after it; `None` if the batch ends inside the record.
fn record(batch: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let rec = batch.get(pos..)?;
    if rec.len() < MIN_HEADER_LEN {
        return None;
    }
    let field = |at: usize| u32::from_ne_bytes(rec[at..at + 4].try_into().unwrap()) as usize;
    let caplen = field(CAPLEN_OFFSET);
    let hdrlen =
        u16::from_ne_bytes(rec[HDRLEN_OFFSET..HDRLEN_OFFSET + 2].try_into().unwrap()) as usize;
    let data = rec.get(hdrlen..hdrlen + caplen)?;
    let next = pos + (hdrlen + caplen).next_multiple_of(ALIGNMENT);
    Some((data, next))
}

/// The first free `/dev/bpfN`. macOS creates the nodes on demand, so a
/// missing one means every device below it is busy.
fn open_device() -> Result<File> {
    for n in 0..MAX_DEVICES {
        let path = format!("/dev/bpf{n}");
        match File::open(&path) {
            Ok(file) => return Ok(file),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                bail!(
                    "Cannot open {path}: {e}; run as root, or grant your user access to the BPF devices (Wireshark's ChmodBPF does this)"
                )
            }
            Err(e) => return Err(e).with_context(|| format!("Cannot open {path}")),
        }
    }
    bail!("All {MAX_DEVICES} BPF devices are busy")
}

/// `arg` is `*mut` because the kernel writes through it for the `BIOCG*`
/// requests.
fn ioctl<T>(fd: libc::c_int, request: libc::c_ulong, arg: *mut T, what: &str) -> Result<()> {
    if unsafe { libc::ioctl(fd, request, arg) } < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("Failed to {what}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record as the kernel writes it: 32-bit timeval, caplen, datalen,
    /// hdrlen, then the bytes, padded to the alignment.
    fn bpf_record(hdrlen: usize, data: &[u8]) -> Vec<u8> {
        let mut rec = vec![0u8; hdrlen];
        rec[CAPLEN_OFFSET..CAPLEN_OFFSET + 4].copy_from_slice(&(data.len() as u32).to_ne_bytes());
        rec[12..16].copy_from_slice(&(data.len() as u32 + 100).to_ne_bytes());
        rec[HDRLEN_OFFSET..HDRLEN_OFFSET + 2].copy_from_slice(&(hdrlen as u16).to_ne_bytes());
        rec.extend_from_slice(data);
        rec.resize(rec.len().next_multiple_of(ALIGNMENT), 0xee);
        rec
    }

    #[test]
    fn walks_records_with_their_own_header_length_and_padding() {
        // Ethernet uses an 18-byte header, loopback 20; a 5-byte payload
        // needs padding before the next record.
        let mut batch = bpf_record(18, b"hello");
        batch.extend(bpf_record(20, b"loop"));
        batch.extend(bpf_record(18, &[7; 40]));

        let (data, next) = record(&batch, 0).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(next, 24);
        let (data, next) = record(&batch, next).unwrap();
        assert_eq!(data, b"loop");
        assert_eq!(next, 48);
        let (data, next) = record(&batch, next).unwrap();
        assert_eq!(data, &[7; 40]);
        assert_eq!(next, batch.len());
        assert!(record(&batch, next).is_none());
    }

    #[test]
    fn truncated_tail_is_rejected() {
        let rec = bpf_record(18, b"hello");
        assert!(record(&rec[..10], 0).is_none());
        assert!(record(&rec[..20], 0).is_none());
        assert!(record(&rec[..23], 0).is_some());
    }
}
