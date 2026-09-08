//! Address text without `core::fmt`.
//!
//! Profiling showed IP and MAC formatting through the generic formatter to
//! be the single cost shared by the CSV, Parquet, and NDJSON encoders.
//! These writers produce exactly the bytes `Display` produces, into a stack
//! buffer, with no formatter machinery in between. Equality with `Display`
//! is pinned by the tests below.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;
use rustflow_core::common::common_flow::FlowType;

/// Longest text produced: `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`.
const CAPACITY: usize = 39;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// The text form of one address, on the stack.
pub struct AddrText {
    buf: [u8; CAPACITY],
    len: usize,
}

impl AddrText {
    const fn empty() -> Self {
        Self {
            buf: [0; CAPACITY],
            len: 0,
        }
    }

    pub fn ip(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => Self::ipv4(a),
            IpAddr::V6(a) => Self::ipv6(a),
        }
    }

    /// `a.b.c.d`, like `Display`.
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        let mut t = Self::empty();
        t.push_ipv4(addr);
        t
    }

    /// RFC 5952 form, like `Display`: lowercase hex, no leading zeros, the
    /// first longest run of two or more zero segments compressed to `::`,
    /// and IPv4-mapped addresses as `::ffff:a.b.c.d`.
    pub fn ipv6(addr: Ipv6Addr) -> Self {
        let mut t = Self::empty();

        if let Some(v4) = addr.to_ipv4_mapped() {
            t.push_bytes(b"::ffff:");
            t.push_ipv4(v4);
            return t;
        }

        let segments = addr.segments();

        // Same search as std: strictly longer runs win, so the first of two
        // equal runs is the one compressed.
        let mut longest = (0, 0);
        let mut current = (0, 0);
        for (i, &segment) in segments.iter().enumerate() {
            if segment == 0 {
                if current.1 == 0 {
                    current.0 = i;
                }
                current.1 += 1;
                if current.1 > longest.1 {
                    longest = current;
                }
            } else {
                current = (0, 0);
            }
        }

        if longest.1 > 1 {
            t.push_segments(&segments[..longest.0]);
            t.push_bytes(b"::");
            t.push_segments(&segments[longest.0 + longest.1..]);
        } else {
            t.push_segments(&segments);
        }
        t
    }

    /// `AA:BB:CC:DD:EE:FF`, like `macaddr`'s `Display`.
    pub fn mac(addr: MacAddr6) -> Self {
        let mut t = Self::empty();
        for (i, byte) in addr.as_bytes().iter().enumerate() {
            if i > 0 {
                t.push(b':');
            }
            t.push(HEX_UPPER[usize::from(byte >> 4)]);
            t.push(HEX_UPPER[usize::from(byte & 0xf)]);
        }
        t
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: every byte pushed is ASCII (digits, hex digits, '.', ':').
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn push(&mut self, b: u8) {
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn push_decimal(&mut self, v: u8) {
        if v >= 100 {
            self.push(b'0' + v / 100);
        }
        if v >= 10 {
            self.push(b'0' + (v / 10) % 10);
        }
        self.push(b'0' + v % 10);
    }

    fn push_ipv4(&mut self, addr: Ipv4Addr) {
        for (i, octet) in addr.octets().iter().enumerate() {
            if i > 0 {
                self.push(b'.');
            }
            self.push_decimal(*octet);
        }
    }

    /// Lowercase hex without leading zeros; `0` for a zero segment.
    fn push_hex(&mut self, v: u16) {
        let mut started = false;
        for shift in [12u32, 8, 4, 0] {
            let digit = ((v >> shift) & 0xf) as u8;
            if digit != 0 || started || shift == 0 {
                self.push(HEX_LOWER[usize::from(digit)]);
                started = true;
            }
        }
    }

    fn push_segments(&mut self, segments: &[u16]) {
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                self.push(b':');
            }
            self.push_hex(*segment);
        }
    }
}

/// The name a flow type serializes as, without going through `Display`.
pub fn flow_type_name(t: FlowType) -> &'static str {
    match t {
        FlowType::NetflowV5 => "NETFLOW_V5",
        FlowType::NetflowV9 => "NETFLOW_V9",
        FlowType::Ipfix => "IPFIX",
        FlowType::SflowV5 => "SFLOW_V5",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic generator so the comparison covers many shapes
    /// without a dependency.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }

        /// Mostly-zero segments, so `::` compression is exercised often.
        fn segment(&mut self) -> u16 {
            let r = self.next();
            match r % 4 {
                0 | 1 => 0,
                2 => (r >> 8) as u16 & 0x000f,
                _ => (r >> 8) as u16,
            }
        }
    }

    #[test]
    fn ipv4_matches_display() {
        for a in [0u8, 1, 9, 10, 99, 100, 199, 200, 255] {
            for b in [0u8, 7, 42, 128, 255] {
                let addr = Ipv4Addr::new(a, b, 255 - a, b / 2);
                assert_eq!(AddrText::ipv4(addr).as_str(), addr.to_string());
            }
        }
    }

    #[test]
    fn ipv6_edge_cases_match_display() {
        for text in [
            "::",
            "::1",
            "1::",
            "1::1",
            "2001:db8::1",
            "2001:db8:0:0:1:0:0:1",
            "1:0:0:1:0:0:1:1",
            "1:0:0:1:0:0:0:1",
            "0:0:1:0:0:0:0:1",
            "0:1:0:0:0:0:0:0",
            "1:0:1:0:1:0:1:0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1",
            "::ffff:1.2.3.4",
            "::ffff:0.0.0.0",
            "::ffff:255.255.255.255",
            "::1.2.3.4",
            "64:ff9b::192.0.2.33",
            "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
            "1:2:3:4:5:6:7:8",
            "0:0:0:0:0:0:0:1",
            "1:0:0:0:0:0:0:0",
            "a:b:c::",
            "::a:b:c",
        ] {
            let addr: Ipv6Addr = text.parse().unwrap();
            assert_eq!(AddrText::ipv6(addr).as_str(), addr.to_string(), "{text}");
        }
    }

    #[test]
    fn many_random_addresses_match_display() {
        let mut rng = Lcg(0x5eed);
        for _ in 0..10_000 {
            let segs: [u16; 8] = std::array::from_fn(|_| rng.segment());
            let v6 = Ipv6Addr::from(segs);
            assert_eq!(AddrText::ipv6(v6).as_str(), v6.to_string(), "{v6:?}");

            let v4 = Ipv4Addr::from(rng.next() as u32);
            assert_eq!(AddrText::ip(IpAddr::V4(v4)).as_str(), v4.to_string());

            let bytes: [u8; 6] = std::array::from_fn(|_| rng.next() as u8);
            let mac = MacAddr6::from(bytes);
            assert_eq!(AddrText::mac(mac).as_str(), mac.to_string(), "{bytes:?}");
        }
    }

    #[test]
    fn mac_is_uppercase_with_colons() {
        let mac = MacAddr6::new(0x00, 0x1a, 0x2b, 0xc3, 0xd4, 0xff);
        assert_eq!(AddrText::mac(mac).as_str(), "00:1A:2B:C3:D4:FF");
        assert_eq!(AddrText::mac(mac).as_str(), mac.to_string());
    }

    #[test]
    fn flow_type_name_matches_display() {
        for t in [
            FlowType::NetflowV5,
            FlowType::NetflowV9,
            FlowType::Ipfix,
            FlowType::SflowV5,
        ] {
            assert_eq!(flow_type_name(t), t.to_string());
        }
    }
}
