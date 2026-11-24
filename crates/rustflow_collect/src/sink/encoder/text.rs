use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustflow_core::common_flow::FlowType;
use rustflow_core::mac_address::MacAddress;

pub trait Text {
    fn write_text(&self, out: &mut Vec<u8>);
}

macro_rules! integer {
    ($($type:ty),*) => {
        $(
            impl Text for $type {
                fn write_text(&self, out: &mut Vec<u8>) {
                    out.extend_from_slice(itoa::Buffer::new().format(*self).as_bytes());
                }
            }
        )*
    };
}
integer!(u8, u16, u32, u64, i64);

impl Text for FlowType {
    fn write_text(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(<&str>::from(self).as_bytes());
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

impl Text for IpAddr {
    fn write_text(&self, out: &mut Vec<u8>) {
        match self {
            IpAddr::V4(ip) => write_ipv4(*ip, out),
            IpAddr::V6(ip) => write_ipv6(*ip, out),
        }
    }
}

fn write_ipv4(ip: Ipv4Addr, out: &mut Vec<u8>) {
    let [a, b, c, d] = ip.octets();
    a.write_text(out);
    for octet in [b, c, d] {
        out.push(b'.');
        octet.write_text(out);
    }
}

fn write_ipv6(ip: Ipv6Addr, out: &mut Vec<u8>) {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        out.extend_from_slice(b"::ffff:");
        write_ipv4(ipv4, out);
        return;
    }
    let segments = ip.segments();
    let mut zeros = 0..0;
    let mut i = 0;
    while i < segments.len() {
        let run = segments[i..].iter().take_while(|&&s| s == 0).count();
        if run > zeros.len() {
            zeros = i..i + run;
        }
        i += run.max(1);
    }
    if zeros.len() < 2 {
        write_segments(&segments, out);
    } else {
        write_segments(&segments[..zeros.start], out);
        out.extend_from_slice(b"::");
        write_segments(&segments[zeros.end..], out);
    }
}

fn write_segments(segments: &[u16], out: &mut Vec<u8>) {
    for (i, &segment) in segments.iter().enumerate() {
        if i > 0 {
            out.push(b':');
        }
        let digits = (19 - segment.leading_zeros() as usize) / 4;
        for digit in (0..digits.max(1)).rev() {
            out.push(HEX[usize::from(segment >> (4 * digit)) & 0xf]);
        }
    }
}

impl Text for MacAddress {
    fn write_text(&self, out: &mut Vec<u8>) {
        for (i, octet) in self.octets().into_iter().enumerate() {
            if i > 0 {
                out.push(b':');
            }
            out.extend_from_slice(&[HEX[usize::from(octet >> 4)], HEX[usize::from(octet & 0xf)]]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: impl Text) -> String {
        let mut out = Vec::new();
        value.write_text(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn matches_display() {
        for ip in [
            "0.0.0.0",
            "255.255.255.255",
            "192.0.2.1",
            "2001:db8::1",
            "::ffff:192.0.2.1",
        ] {
            assert_eq!(text(ip.parse::<IpAddr>().unwrap()), ip);
        }
        let mac = MacAddress::from([0x02, 0x00, 0xab, 0x0f, 0xf0, 0xff]);
        assert_eq!(text(mac), mac.to_string());
        assert_eq!(text(FlowType::NetflowV9), FlowType::NetflowV9.to_string());
        assert_eq!(text(i64::MIN), i64::MIN.to_string());
    }

    #[test]
    fn ipv6_matches_display_for_every_zero_pattern() {
        for zeros in 0..=u8::MAX {
            for value in [0x1, 0xab, 0xf00, 0xabcd] {
                let segments: [u16; 8] =
                    std::array::from_fn(|i| if zeros & (1 << i) != 0 { 0 } else { value });
                let ip = IpAddr::from(segments);
                assert_eq!(text(ip), ip.to_string());
            }
        }
    }
}
