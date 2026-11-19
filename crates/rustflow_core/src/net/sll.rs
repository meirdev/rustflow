use std::fmt;

use super::{Protocol, clipped, octets_at};

const SLL_LENGTH: usize = 16;

const SLL2_LENGTH: usize = 20;

/// Netlink messages: the protocol field is a Netlink family, not an
/// EtherType.
const ARPHRD_NETLINK: u16 = 824;
/// 802.11 frames behind a radiotap header: the protocol field is unused.
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sll<'a> {
    header: &'a [u8],
}

impl Sll<'_> {
    pub fn protocol(&self) -> Option<Protocol> {
        ether_type(self.header, 2, 14)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sll2<'a> {
    header: &'a [u8],
}

impl Sll2<'_> {
    pub fn protocol(&self) -> Option<Protocol> {
        ether_type(self.header, 8, 0)
    }
}

impl fmt::Debug for Sll<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sll")
            .field("protocol", &self.protocol())
            .finish()
    }
}

impl fmt::Debug for Sll2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sll2")
            .field("protocol", &self.protocol())
            .finish()
    }
}

pub fn sll<'a>(input: &mut &'a [u8]) -> Sll<'a> {
    Sll {
        header: clipped(input, SLL_LENGTH),
    }
}

pub fn sll2<'a>(input: &mut &'a [u8]) -> Sll2<'a> {
    Sll2 {
        header: clipped(input, SLL2_LENGTH),
    }
}

fn ether_type(header: &[u8], arphrd_at: usize, protocol_at: usize) -> Option<Protocol> {
    let arphrd = octets_at(header, arphrd_at).map(u16::from_be_bytes)?;
    if matches!(arphrd, ARPHRD_NETLINK | ARPHRD_IEEE80211_RADIOTAP) {
        return None;
    }
    octets_at(header, protocol_at)
        .map(u16::from_be_bytes)
        .map(Protocol::from_ether_type)
}
