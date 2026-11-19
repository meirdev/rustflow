use std::fmt;

use super::{clipped, octets_at};

const HEADER_LENGTH: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tcp<'a> {
    header: &'a [u8],
}

impl Tcp<'_> {
    pub fn source(&self) -> Option<u16> {
        octets_at(self.header, 0).map(u16::from_be_bytes)
    }

    pub fn destination(&self) -> Option<u16> {
        octets_at(self.header, 2).map(u16::from_be_bytes)
    }

    pub fn flags(&self) -> Option<u8> {
        octets_at(self.header, 13).map(u8::from_be_bytes)
    }
}

impl fmt::Debug for Tcp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tcp")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("flags", &self.flags())
            .finish()
    }
}

pub fn tcp<'a>(input: &mut &'a [u8]) -> Tcp<'a> {
    Tcp {
        header: clipped(input, HEADER_LENGTH),
    }
}
