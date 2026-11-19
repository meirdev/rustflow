use std::fmt;

use super::{Protocol, clipped, octets_at};
use crate::mac_address::MacAddress;

const ETHERNET_LENGTH: usize = 14;
const VLAN_LENGTH: usize = 4;

/// The low 12 bits of the tag control information.
const VLAN_IDENTIFIER_MASK: u16 = 0x0fff;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ethernet<'a> {
    header: &'a [u8],
}

impl Ethernet<'_> {
    pub fn destination(&self) -> Option<MacAddress> {
        octets_at(self.header, 0).map(MacAddress::from)
    }

    pub fn source(&self) -> Option<MacAddress> {
        octets_at(self.header, 6).map(MacAddress::from)
    }

    /// An 802.3 length when below 0x0600.
    pub fn ethertype(&self) -> Option<u16> {
        octets_at(self.header, 12).map(u16::from_be_bytes)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.ethertype().map(Protocol::from_ether_type)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Vlan<'a> {
    header: &'a [u8],
}

impl Vlan<'_> {
    pub fn vlan_identifier(&self) -> Option<u16> {
        octets_at(self.header, 0).map(|tci| u16::from_be_bytes(tci) & VLAN_IDENTIFIER_MASK)
    }

    pub fn ethertype(&self) -> Option<u16> {
        octets_at(self.header, 2).map(u16::from_be_bytes)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.ethertype().map(Protocol::from_ether_type)
    }
}

impl fmt::Debug for Ethernet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ethernet")
            .field("destination", &self.destination())
            .field("source", &self.source())
            .field("ethertype", &self.ethertype())
            .finish()
    }
}

impl fmt::Debug for Vlan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vlan")
            .field("vlan_identifier", &self.vlan_identifier())
            .field("ethertype", &self.ethertype())
            .finish()
    }
}

pub fn ethernet<'a>(input: &mut &'a [u8]) -> Ethernet<'a> {
    Ethernet {
        header: clipped(input, ETHERNET_LENGTH),
    }
}

pub fn vlan<'a>(input: &mut &'a [u8]) -> Vlan<'a> {
    Vlan {
        header: clipped(input, VLAN_LENGTH),
    }
}
