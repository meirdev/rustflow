use std::fmt;

use super::{Protocol, clipped, octets_at};

const HEADER_LENGTH: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Udp<'a> {
    header: &'a [u8],
}

impl Udp<'_> {
    pub fn source(&self) -> Option<u16> {
        octets_at(self.header, 0).map(u16::from_be_bytes)
    }

    pub fn destination(&self) -> Option<u16> {
        octets_at(self.header, 2).map(u16::from_be_bytes)
    }

    pub fn length(&self) -> Option<u16> {
        octets_at(self.header, 4).map(u16::from_be_bytes)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.destination().map(Protocol::from_udp_port)
    }
}

impl fmt::Debug for Udp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Udp")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("length", &self.length())
            .finish()
    }
}

pub fn udp<'a>(input: &mut &'a [u8]) -> Udp<'a> {
    Udp {
        header: clipped(input, HEADER_LENGTH),
    }
}
