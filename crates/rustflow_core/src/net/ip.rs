use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Protocol, clipped, octets_at};

/// The IPv4 header without options.
const IPV4_MIN_LENGTH: usize = 20;
/// The low 13 bits of the flags and fragment offset word.
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

const IPV6_HEADER_LENGTH: usize = 40;
const IPV6_FLOW_LABEL_MASK: u32 = 0x000f_ffff;

const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTHENTICATION: u8 = 51;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const IPV6_MOBILITY: u8 = 135;
const IPV6_HOST_IDENTITY: u8 = 139;
const IPV6_SHIM6: u8 = 140;
const IPV6_FRAGMENT_HEADER_LENGTH: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    header: &'a [u8],
}

impl Ipv4<'_> {
    pub fn tos(&self) -> Option<u8> {
        octets_at(self.header, 1).map(u8::from_be_bytes)
    }

    pub fn identification(&self) -> Option<u16> {
        octets_at(self.header, 4).map(u16::from_be_bytes)
    }

    /// In 8-octet units.
    pub fn fragment_offset(&self) -> Option<u16> {
        octets_at(self.header, 6).map(|word| u16::from_be_bytes(word) & IPV4_FRAGMENT_OFFSET_MASK)
    }

    pub fn ttl(&self) -> Option<u8> {
        octets_at(self.header, 8).map(u8::from_be_bytes)
    }

    pub fn next_level_protocol(&self) -> Option<u8> {
        octets_at(self.header, 9).map(u8::from_be_bytes)
    }

    pub fn source(&self) -> Option<Ipv4Addr> {
        octets_at(self.header, 12).map(Ipv4Addr::from)
    }

    pub fn destination(&self) -> Option<Ipv4Addr> {
        octets_at(self.header, 16).map(Ipv4Addr::from)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        if self.fragment_offset()? != 0 {
            return Some(Protocol::Fragment);
        }
        self.next_level_protocol().map(Protocol::from_ip_protocol)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ipv6<'a> {
    header: &'a [u8],
    payload: Option<Protocol>,
}

impl Ipv6<'_> {
    pub fn traffic_class(&self) -> Option<u8> {
        octets_at(self.header, 0).map(|word| (u16::from_be_bytes(word) >> 4) as u8)
    }

    pub fn flow_label(&self) -> Option<u32> {
        octets_at(self.header, 0).map(|word| u32::from_be_bytes(word) & IPV6_FLOW_LABEL_MASK)
    }

    pub fn hop_limit(&self) -> Option<u8> {
        octets_at(self.header, 7).map(u8::from_be_bytes)
    }

    pub fn source(&self) -> Option<Ipv6Addr> {
        octets_at(self.header, 8).map(Ipv6Addr::from)
    }

    pub fn destination(&self) -> Option<Ipv6Addr> {
        octets_at(self.header, 24).map(Ipv6Addr::from)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.payload
    }
}

impl fmt::Debug for Ipv4<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("protocol", &self.protocol())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Ipv6<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv6")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("protocol", &self.protocol())
            .finish_non_exhaustive()
    }
}

pub fn ipv4<'a>(input: &mut &'a [u8]) -> Ipv4<'a> {
    let length = input
        .first()
        .map(|&first| usize::from(first & 0x0f) * 4)
        .filter(|&length| length >= IPV4_MIN_LENGTH)
        .unwrap_or(IPV4_MIN_LENGTH);
    Ipv4 {
        header: clipped(input, length),
    }
}

pub fn ipv6<'a>(input: &mut &'a [u8]) -> Ipv6<'a> {
    let header = clipped(input, IPV6_HEADER_LENGTH);
    let payload = match header.len() {
        IPV6_HEADER_LENGTH => extension_headers(input, header[6]),
        _ => None,
    };
    Ipv6 { header, payload }
}

/// Steps over the extension headers that start with `next_header`, giving
/// what follows them; `None` when they are clipped before their end.
fn extension_headers(input: &mut &[u8], mut next_header: u8) -> Option<Protocol> {
    loop {
        let length = match next_header {
            // Next header, length in 8-octet units beyond the first.
            IPV6_HOP_BY_HOP
            | IPV6_ROUTING
            | IPV6_DESTINATION_OPTIONS
            | IPV6_MOBILITY
            | IPV6_HOST_IDENTITY
            | IPV6_SHIM6 => (usize::from(*input.get(1)?) + 1) * 8,
            // Next header, length in 4-octet units beyond the first two
            // (RFC 4302).
            IPV6_AUTHENTICATION => (usize::from(*input.get(1)?) + 2) * 4,
            // Next header, reserved, offset (13 bits) and flags,
            // identification.
            IPV6_FRAGMENT => IPV6_FRAGMENT_HEADER_LENGTH,
            _ => return Some(Protocol::from_ip_protocol(next_header)),
        };
        let (header, rest) = input.split_at_checked(length)?;
        *input = rest;
        if next_header == IPV6_FRAGMENT && u16::from_be_bytes([header[2], header[3]]) >> 3 != 0 {
            return Some(Protocol::Fragment);
        }
        next_header = header[0];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(first: u8, flags_and_offset: u16, protocol: u8, options: &[u8]) -> Vec<u8> {
        let mut out = vec![first, 0xb9, 0, 40, 0, 1];
        out.extend(flags_and_offset.to_be_bytes());
        out.extend([64, protocol, 0x12, 0x34]);
        out.extend([192, 0, 2, 1, 10, 0, 0, 1]);
        out.extend(options);
        out
    }

    fn ipv6_header(next_header: u8) -> Vec<u8> {
        // Traffic class 0xab, flow label 0x12345.
        let mut out = vec![0x6a, 0xb1, 0x23, 0x45, 0, 8, next_header, 64];
        out.extend(Ipv6Addr::LOCALHOST.octets());
        out.extend(Ipv6Addr::UNSPECIFIED.octets());
        out
    }

    /// The protocol after an IPv4 header, and the octets left.
    fn after_ipv4(bytes: &[u8]) -> (Option<Protocol>, Vec<u8>) {
        let mut input = bytes;
        let header = ipv4(&mut input);
        (header.protocol(), input.to_vec())
    }

    fn after_ipv6(bytes: &[u8]) -> (Option<Protocol>, Vec<u8>) {
        let mut input = bytes;
        let header = ipv6(&mut input);
        (header.protocol(), input.to_vec())
    }

    #[test]
    fn ipv4_header_fields() {
        let bytes = ipv4_header(0x45, 0x4000, 17, &[]);
        let header = ipv4(&mut &bytes[..]);
        assert_eq!(
            (
                header.tos(),
                header.identification(),
                header.fragment_offset()
            ),
            (Some(0xb9), Some(1), Some(0))
        );
        assert_eq!(
            (header.ttl(), header.next_level_protocol()),
            (Some(64), Some(17))
        );
        assert_eq!(
            (header.source(), header.destination()),
            (
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                Some(Ipv4Addr::new(10, 0, 0, 1))
            )
        );
    }

    #[test]
    fn ipv4_names_its_payload() {
        for (protocol, expected) in [
            (17, Protocol::Udp),
            (47, Protocol::Gre),
            (4, Protocol::Ipv4),
            (41, Protocol::Ipv6),
            (137, Protocol::Mpls),
            (6, Protocol::Tcp),
            (1, Protocol::Icmp),
            (58, Protocol::Icmpv6),
            (132, Protocol::IpProtocol(132)),
        ] {
            let bytes = [ipv4_header(0x45, 0, protocol, &[]), b"payload".to_vec()].concat();
            assert_eq!(after_ipv4(&bytes), (Some(expected), b"payload".to_vec()));
        }
    }

    #[test]
    fn ipv4_options_are_skipped() {
        let bytes = [ipv4_header(0x47, 0, 17, &[0xaa; 8]), b"payload".to_vec()].concat();
        assert_eq!(
            after_ipv4(&bytes),
            (Some(Protocol::Udp), b"payload".to_vec())
        );
        // A header length below the header itself reads as 20 octets.
        let bytes = [ipv4_header(0x44, 0, 17, &[]), b"payload".to_vec()].concat();
        assert_eq!(
            after_ipv4(&bytes),
            (Some(Protocol::Udp), b"payload".to_vec())
        );
    }

    #[test]
    fn a_clipped_ipv4_header_gives_what_it_has() {
        let bytes = ipv4_header(0x45, 0, 17, &[]);
        let header = ipv4(&mut &bytes[..14]);
        assert_eq!(
            (header.protocol(), header.source(), header.destination()),
            (Some(Protocol::Udp), None, None)
        );
        assert_eq!(ipv4(&mut &bytes[..0]).protocol(), None);
    }

    #[test]
    fn ipv4_later_fragments_have_no_header_behind_them() {
        // More fragments, offset 0: the first fragment.
        let first = ipv4_header(0x45, 0x2000, 17, &[]);
        assert_eq!(after_ipv4(&first), (Some(Protocol::Udp), vec![]));

        let bytes = ipv4_header(0x45, 0x2004, 17, &[]);
        let later = ipv4(&mut &bytes[..]);
        assert_eq!(later.fragment_offset(), Some(4));
        assert_eq!(later.protocol(), Some(Protocol::Fragment));
    }

    #[test]
    fn ipv6_header_fields() {
        let bytes = ipv6_header(17);
        let header = ipv6(&mut &bytes[..]);
        assert_eq!(
            (
                header.traffic_class(),
                header.flow_label(),
                header.hop_limit()
            ),
            (Some(0xab), Some(0x12345), Some(64))
        );
        assert_eq!(
            (header.source(), header.destination(), header.protocol()),
            (
                Some(Ipv6Addr::LOCALHOST),
                Some(Ipv6Addr::UNSPECIFIED),
                Some(Protocol::Udp)
            )
        );
        // Clipped: the addresses it has, and nothing of what follows.
        let header = ipv6(&mut &bytes[..39]);
        assert_eq!(
            (header.source(), header.destination(), header.protocol()),
            (Some(Ipv6Addr::LOCALHOST), None, None)
        );
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        let bytes = [
            ipv6_header(0),
            // Hop-by-hop, 8 octets, then routing.
            [&[43, 0][..], &[0; 6]].concat(),
            // Routing, 16 octets, then authentication.
            [&[51, 1][..], &[0; 14]].concat(),
            // Authentication, (1 + 2) * 4 = 12 octets, then GRE.
            [&[47, 1][..], &[0; 10]].concat(),
            b"payload".to_vec(),
        ]
        .concat();
        assert_eq!(
            after_ipv6(&bytes),
            (Some(Protocol::Gre), b"payload".to_vec())
        );

        // An extension header longer than what is there.
        let clipped = [ipv6_header(60), vec![17, 2, 0, 0]].concat();
        assert_eq!(after_ipv6(&clipped).0, None);
        // ESP hides what follows it.
        assert_eq!(
            after_ipv6(&ipv6_header(50)),
            (Some(Protocol::IpProtocol(50)), vec![])
        );
    }

    #[test]
    fn ipv6_later_fragments_have_no_header_behind_them() {
        // Fragment header: next header UDP, offset 0 with more fragments.
        let first = [ipv6_header(44), vec![17, 0, 0x00, 0x01, 0, 0, 0, 9]].concat();
        assert_eq!(after_ipv6(&first), (Some(Protocol::Udp), vec![]));
        // Offset 1 (in 8-octet units).
        let later = [ipv6_header(44), vec![17, 0, 0x00, 0x08, 0, 0, 0, 9]].concat();
        assert_eq!(after_ipv6(&later), (Some(Protocol::Fragment), vec![]));
    }
}
