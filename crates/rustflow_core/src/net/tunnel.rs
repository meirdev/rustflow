use std::fmt;

use super::{Protocol, clipped, octets_at};

const VXLAN_LENGTH: usize = 8;

/// Before options, whose length in 4-octet words is in the low 6 bits of
/// the first octet.
const GENEVE_LENGTH: usize = 8;
const GENEVE_OPTIONS_LENGTH_MASK: u8 = 0x3f;

/// Before the optional fields that its flags announce, 4 octets each.
const GRE_LENGTH: usize = 4;
const GRE_FIELD_LENGTH: usize = 4;
const GRE_CHECKSUM: u16 = 0x8000;
/// RFC 1701 routing, whose fields are of variable length.
const GRE_ROUTING: u16 = 0x4000;
const GRE_KEY: u16 = 0x2000;
const GRE_SEQUENCE: u16 = 0x1000;
const GRE_VERSION_MASK: u16 = 0x0007;

const ERSPAN_I_II: u16 = 0x88be;
const ERSPAN_III: u16 = 0x22eb;
/// Type II, which a GRE sequence number tells from type I (no header).
const ERSPAN_II_LENGTH: usize = 8;
/// Type III, and its platform subheader when the low bit of its last octet
/// is set.
const ERSPAN_III_LENGTH: usize = 12;
const ERSPAN_III_PLATFORM_LENGTH: usize = 8;

const MPLS_ENTRY_LENGTH: usize = 4;
const MPLS_BOTTOM_OF_STACK: u32 = 0x100;
/// A pseudowire control word (RFC 4385).
const MPLS_CONTROL_WORD_LENGTH: usize = 4;

/// A VXLAN header (RFC 7348), as much of it as there is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Vxlan<'a> {
    header: &'a [u8],
}

impl Vxlan<'_> {
    pub fn vni(&self) -> Option<u32> {
        octets_at(self.header, 4).map(|word| u32::from_be_bytes(word) >> 8)
    }

    /// An Ethernet frame, once the whole header is there.
    pub fn protocol(&self) -> Option<Protocol> {
        (self.header.len() == VXLAN_LENGTH).then_some(Protocol::Ethernet)
    }
}

/// A Geneve header (RFC 8926), with its options, as much of it as there is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Geneve<'a> {
    header: &'a [u8],
}

impl Geneve<'_> {
    pub fn vni(&self) -> Option<u32> {
        octets_at(self.header, 4).map(|word| u32::from_be_bytes(word) >> 8)
    }

    /// By its protocol type, an EtherType.
    pub fn protocol(&self) -> Option<Protocol> {
        octets_at(self.header, 2)
            .map(u16::from_be_bytes)
            .map(Protocol::from_ether_type)
    }
}

/// A GRE header (RFC 2784, RFC 2890), with its optional fields and an ERSPAN
/// header behind it, as much of it as there is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Gre<'a> {
    header: &'a [u8],
}

impl Gre<'_> {
    /// By its protocol type, an EtherType; ERSPAN carries an Ethernet frame.
    /// `None` with RFC 1701 routing or another version, such as PPTP's,
    /// whose headers are laid out otherwise.
    pub fn protocol(&self) -> Option<Protocol> {
        let flags = octets_at(self.header, 0).map(u16::from_be_bytes)?;
        if flags & (GRE_ROUTING | GRE_VERSION_MASK) != 0 {
            return None;
        }
        octets_at(self.header, 2)
            .map(u16::from_be_bytes)
            .map(|protocol_type| match protocol_type {
                ERSPAN_I_II | ERSPAN_III => Protocol::Ethernet,
                protocol_type => Protocol::from_ether_type(protocol_type),
            })
    }
}

/// An MPLS label stack (RFC 3032), to its bottom, as much of it as there is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mpls<'a> {
    header: &'a [u8],
    payload: Option<Protocol>,
}

impl Mpls<'_> {
    /// MPLS does not say what it carries, so this is a guess from the
    /// payload's first nibble: 4 is IPv4, 6 is IPv6, 0 is a pseudowire
    /// control word, which is stepped over, then Ethernet, and anything else
    /// is Ethernet. An Ethernet frame sent without a control word whose
    /// address starts with 4 or 6 is therefore taken for IP. `None` when the
    /// stack is clipped before its bottom or its payload.
    pub fn protocol(&self) -> Option<Protocol> {
        self.payload
    }
}

impl fmt::Debug for Vxlan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vxlan").field("vni", &self.vni()).finish()
    }
}

impl fmt::Debug for Geneve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Geneve")
            .field("vni", &self.vni())
            .field("protocol", &self.protocol())
            .finish()
    }
}

impl fmt::Debug for Gre<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gre")
            .field("protocol", &self.protocol())
            .finish()
    }
}

impl fmt::Debug for Mpls<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mpls")
            .field("protocol", &self.protocol())
            .finish()
    }
}

/// As much of the header as there is, perhaps none of it.
pub fn vxlan<'a>(input: &mut &'a [u8]) -> Vxlan<'a> {
    Vxlan {
        header: clipped(input, VXLAN_LENGTH),
    }
}

/// As much of the header and its options as there is, perhaps none of it.
pub fn geneve<'a>(input: &mut &'a [u8]) -> Geneve<'a> {
    let length = input.first().map_or(GENEVE_LENGTH, |&first| {
        GENEVE_LENGTH + usize::from(first & GENEVE_OPTIONS_LENGTH_MASK) * 4
    });
    Geneve {
        header: clipped(input, length),
    }
}

/// As much of the header, its optional fields and an ERSPAN header behind
/// it as there is, perhaps none of it.
pub fn gre<'a>(input: &mut &'a [u8]) -> Gre<'a> {
    let flags = octets_at(input, 0).map_or(0, u16::from_be_bytes);
    let mut length = GRE_LENGTH;
    for flag in [GRE_CHECKSUM, GRE_KEY, GRE_SEQUENCE] {
        if flags & flag != 0 {
            length += GRE_FIELD_LENGTH;
        }
    }
    length += match octets_at(input, 2).map(u16::from_be_bytes) {
        Some(ERSPAN_I_II) if flags & GRE_SEQUENCE != 0 => ERSPAN_II_LENGTH,
        Some(ERSPAN_III) => match input.get(length + ERSPAN_III_LENGTH - 1) {
            Some(last) if last & 0x01 != 0 => ERSPAN_III_LENGTH + ERSPAN_III_PLATFORM_LENGTH,
            _ => ERSPAN_III_LENGTH,
        },
        _ => 0,
    };
    Gre {
        header: clipped(input, length),
    }
}

/// As much of the label stack, and a control word after it, as there is,
/// perhaps none of it.
pub fn mpls<'a>(input: &mut &'a [u8]) -> Mpls<'a> {
    let mut length = 0;
    loop {
        let Some(entry) = octets_at(input, length).map(u32::from_be_bytes) else {
            // Clipped before the bottom of the stack.
            return Mpls {
                header: clipped(input, input.len()),
                payload: None,
            };
        };
        length += MPLS_ENTRY_LENGTH;
        if entry & MPLS_BOTTOM_OF_STACK != 0 {
            break;
        }
    }
    let payload = input.get(length).map(|first| match first >> 4 {
        4 => Protocol::Ipv4,
        6 => Protocol::Ipv6,
        0 => {
            length += MPLS_CONTROL_WORD_LENGTH;
            Protocol::Ethernet
        }
        _ => Protocol::Ethernet,
    });
    Mpls {
        header: clipped(input, length),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protocol after a header, and the octets left.
    fn after<'a, T>(
        bytes: &'a [u8],
        parse: impl Fn(&mut &'a [u8]) -> T,
        protocol: impl Fn(&T) -> Option<Protocol>,
    ) -> (Option<Protocol>, Vec<u8>) {
        let mut input = bytes;
        let header = parse(&mut input);
        (protocol(&header), input.to_vec())
    }

    fn after_gre(bytes: &[u8]) -> (Option<Protocol>, Vec<u8>) {
        after(bytes, gre, Gre::protocol)
    }

    fn after_mpls(bytes: &[u8]) -> (Option<Protocol>, Vec<u8>) {
        after(bytes, mpls, Mpls::protocol)
    }

    #[test]
    fn vxlan_header() {
        let bytes = [&[0x08, 0, 0, 0, 0x01, 0x02, 0x03, 0][..], b"frame"].concat();
        let mut input = &bytes[..];
        let header = vxlan(&mut input);
        assert_eq!(
            (header.vni(), header.protocol()),
            (Some(0x01_0203), Some(Protocol::Ethernet))
        );
        assert_eq!(input, b"frame");

        // Clipped: the VNI, but nothing to step to.
        let header = vxlan(&mut &bytes[..7]);
        assert_eq!((header.vni(), header.protocol()), (None, None));
    }

    /// Version and options length in words, flags, protocol, VNI, and
    /// four octets of options.
    fn geneve_packet(first: u8, protocol: u16) -> Vec<u8> {
        let header = [&[first, 0x40][..], &protocol.to_be_bytes(), &[0, 0, 1, 0]].concat();
        [&header[..], &[0xaa; 4], b"inner"].concat()
    }

    #[test]
    fn geneve_options_are_skipped() {
        let bytes = geneve_packet(0x01, 0x6558);
        let mut input = &bytes[..];
        let header = geneve(&mut input);
        assert_eq!(
            (header.vni(), header.protocol()),
            (Some(1), Some(Protocol::Ethernet))
        );
        assert_eq!(input, b"inner");

        let bytes = geneve_packet(0x01, 0x0800);
        assert_eq!(geneve(&mut &bytes[..]).protocol(), Some(Protocol::Ipv4));
        // Options longer than what is there: all of it is the header.
        let bytes = geneve_packet(0x3f, 0x0800);
        let mut input = &bytes[..];
        geneve(&mut input);
        assert!(input.is_empty());
    }

    #[test]
    fn gre_names_its_payload() {
        let packet = |protocol: u16| [&[0, 0][..], &protocol.to_be_bytes(), b"inner"].concat();
        for (protocol, expected) in [
            (0x0800, Protocol::Ipv4),
            (0x86dd, Protocol::Ipv6),
            (0x6558, Protocol::Ethernet),
            (0x8847, Protocol::Mpls),
            (0x880b, Protocol::EtherType(0x880b)),
        ] {
            assert_eq!(
                after_gre(&packet(protocol)),
                (Some(expected), b"inner".to_vec())
            );
        }
    }

    #[test]
    fn gre_optional_fields_are_stepped_over() {
        // Checksum (and reserved), key and sequence number.
        let optional = [0x12, 0x34, 0, 0, 0, 0, 0, 7, 0, 0, 0, 9];
        let bytes = [&[0xb0, 0x00, 0x08, 0x00][..], &optional, b"inner"].concat();
        assert_eq!(after_gre(&bytes), (Some(Protocol::Ipv4), b"inner".to_vec()));

        // Key only.
        let bytes = [&[0x20, 0x00, 0x08, 0x00][..], &[0, 0, 0, 7], b"inner"].concat();
        assert_eq!(after_gre(&bytes), (Some(Protocol::Ipv4), b"inner".to_vec()));
    }

    #[test]
    fn gre_with_routing_or_another_version_says_nothing_of_its_payload() {
        for flags in [[0x40, 0x00], [0x00, 0x01]] {
            let packet = [&flags[..], &[0x08, 0x00], b"inner"].concat();
            assert_eq!(after_gre(&packet).0, None, "flags {flags:?}");
        }
    }

    #[test]
    fn erspan_headers_are_skipped() {
        let type_i = [&[0x00, 0x00, 0x88, 0xbe][..], b"frame"].concat();
        // Type II: the GRE sequence number, then an 8-octet ERSPAN header.
        let type_ii = [&[0x10, 0x00, 0x88, 0xbe][..], &[0; 4], &[0; 8], b"frame"].concat();
        let type_iii = [&[0x00, 0x00, 0x22, 0xeb][..], &[0; 12], b"frame"].concat();
        let mut with_platform = [0; 20];
        with_platform[11] = 0x01;
        let type_iii_platform = [&[0x00, 0x00, 0x22, 0xeb][..], &with_platform, b"frame"].concat();
        for packet in [type_i, type_ii, type_iii, type_iii_platform] {
            assert_eq!(
                after_gre(&packet),
                (Some(Protocol::Ethernet), b"frame".to_vec())
            );
        }
    }

    /// Label 16, traffic class 5, TTL 64: not the bottom of the stack.
    const LABEL: [u8; 4] = [0x00, 0x01, 0x0a, 0x40];
    /// Label 32, TTL 63: the bottom of the stack.
    const BOTTOM: [u8; 4] = [0x00, 0x02, 0x01, 0x3f];

    #[test]
    fn an_mpls_stack_is_read_to_its_bottom() {
        let bytes = [&LABEL[..], &BOTTOM, &[0x45, 0, 0, 20]].concat();
        assert_eq!(
            after_mpls(&bytes),
            (Some(Protocol::Ipv4), vec![0x45, 0, 0, 20])
        );

        // No bottom of stack, and nothing after it.
        assert_eq!(after_mpls(&[&LABEL[..], &LABEL].concat()), (None, vec![]));
        assert_eq!(after_mpls(&BOTTOM), (None, vec![]));
    }

    #[test]
    fn an_mpls_payload_is_guessed_from_its_first_nibble() {
        let after = |payload: &[u8]| after_mpls(&[&BOTTOM[..], payload].concat());

        assert_eq!(
            after(&[0x60, 0, 0, 0]),
            (Some(Protocol::Ipv6), vec![0x60, 0, 0, 0])
        );
        // A pseudowire control word is skipped.
        assert_eq!(
            after(&[&[0; 4][..], b"frame"].concat()),
            (Some(Protocol::Ethernet), b"frame".to_vec())
        );
        assert_eq!(
            after(&[0xaa, 0xbb]),
            (Some(Protocol::Ethernet), vec![0xaa, 0xbb])
        );
    }
}
