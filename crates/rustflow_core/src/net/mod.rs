mod icmp;
mod ip;
mod link;
mod sll;
mod tcp;
mod tunnel;
mod udp;

pub use self::icmp::{Icmp, icmp};
pub use self::ip::{Ipv4, Ipv6, ipv4, ipv6};
pub use self::link::{Ethernet, Vlan, ethernet, vlan};
pub use self::sll::{Sll, Sll2, sll, sll2};
pub use self::tcp::{Tcp, tcp};
pub use self::tunnel::{Geneve, Gre, Mpls, Vxlan, geneve, gre, mpls, vxlan};
pub use self::udp::{Udp, udp};

pub(crate) const ETHER_TYPE_IPV4: u16 = 0x0800;
pub(crate) const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_MPLS_UNICAST: u16 = 0x8847;
const ETHER_TYPE_MPLS_MULTICAST: u16 = 0x8848;
/// Transparent Ethernet bridging: how GRE and Geneve name an inner
/// Ethernet frame.
const ETHER_TYPE_TRANSPARENT_ETHERNET_BRIDGING: u16 = 0x6558;
/// 802.1Q, 802.1ad and the older QinQ tag.
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_SERVICE_VLAN: u16 = 0x88a8;
const ETHER_TYPE_QINQ: u16 = 0x9100;

const IP_PROTOCOL_IPV4: u8 = 4;
pub(crate) const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_IPV6: u8 = 41;
const IP_PROTOCOL_GRE: u8 = 47;
const IP_PROTOCOL_ICMPV6: u8 = 58;
/// MPLS in IP (RFC 4023).
const IP_PROTOCOL_MPLS: u8 = 137;

const UDP_PORT_VXLAN: u16 = 4789;
const UDP_PORT_GENEVE: u16 = 6081;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
    /// An Ethernet frame; see [`ethernet`].
    Ethernet,
    /// A VLAN tag; see [`vlan`].
    Vlan,
    /// See [`ipv4`].
    Ipv4,
    /// See [`ipv6`].
    Ipv6,
    /// An MPLS label stack; see [`mpls`].
    Mpls,
    /// See [`tcp`].
    Tcp,
    /// See [`icmp`].
    Icmp,
    /// See [`icmp`].
    Icmpv6,
    /// See [`udp`].
    Udp,
    /// See [`gre`].
    Gre,
    /// See [`vxlan`].
    Vxlan,
    /// See [`geneve`].
    Geneve,
    /// Something this module does not step over, by its EtherType.
    EtherType(u16),
    /// Something this module does not step over, by its IP protocol number.
    IpProtocol(u8),
    /// A UDP payload that is not a tunnel this module knows, by its
    /// destination port.
    UdpPort(u16),
    /// The rest of a fragment other than the first: the middle of some
    /// payload, not a header.
    Fragment,
}

impl Protocol {
    pub fn from_ether_type(ether_type: u16) -> Self {
        match ether_type {
            ETHER_TYPE_IPV4 => Self::Ipv4,
            ETHER_TYPE_IPV6 => Self::Ipv6,
            ETHER_TYPE_MPLS_UNICAST | ETHER_TYPE_MPLS_MULTICAST => Self::Mpls,
            ETHER_TYPE_TRANSPARENT_ETHERNET_BRIDGING => Self::Ethernet,
            ETHER_TYPE_VLAN | ETHER_TYPE_SERVICE_VLAN | ETHER_TYPE_QINQ => Self::Vlan,
            other => Self::EtherType(other),
        }
    }

    pub fn from_ip_protocol(ip_protocol: u8) -> Self {
        match ip_protocol {
            IP_PROTOCOL_IPV4 => Self::Ipv4,
            IP_PROTOCOL_IPV6 => Self::Ipv6,
            IP_PROTOCOL_ICMP => Self::Icmp,
            IP_PROTOCOL_ICMPV6 => Self::Icmpv6,
            IP_PROTOCOL_TCP => Self::Tcp,
            IP_PROTOCOL_UDP => Self::Udp,
            IP_PROTOCOL_GRE => Self::Gre,
            IP_PROTOCOL_MPLS => Self::Mpls,
            other => Self::IpProtocol(other),
        }
    }

    /// The IP protocol number, the reverse of
    /// [`from_ip_protocol`](Self::from_ip_protocol); `None` for what is not
    /// carried over IP by a protocol number, such as a fragment.
    pub fn ip_protocol(self) -> Option<u8> {
        Some(match self {
            Self::Ipv4 => IP_PROTOCOL_IPV4,
            Self::Ipv6 => IP_PROTOCOL_IPV6,
            Self::Icmp => IP_PROTOCOL_ICMP,
            Self::Icmpv6 => IP_PROTOCOL_ICMPV6,
            Self::Tcp => IP_PROTOCOL_TCP,
            Self::Udp => IP_PROTOCOL_UDP,
            Self::Gre => IP_PROTOCOL_GRE,
            Self::Mpls => IP_PROTOCOL_MPLS,
            Self::IpProtocol(protocol) => protocol,
            Self::Ethernet
            | Self::Vlan
            | Self::Vxlan
            | Self::Geneve
            | Self::EtherType(_)
            | Self::UdpPort(_)
            | Self::Fragment => return None,
        })
    }

    /// By UDP destination port.
    pub fn from_udp_port(port: u16) -> Self {
        match port {
            UDP_PORT_VXLAN => Self::Vxlan,
            UDP_PORT_GENEVE => Self::Geneve,
            other => Self::UdpPort(other),
        }
    }
}

fn clipped<'a>(input: &mut &'a [u8], length: usize) -> &'a [u8] {
    let (header, rest) = input.split_at(input.len().min(length));
    *input = rest;
    header
}

fn octets_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..)?.first_chunk().copied()
}
