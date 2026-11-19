use std::fmt;

use super::{clipped, octets_at};

const HEADER_LENGTH: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Icmp<'a> {
    header: &'a [u8],
}

impl Icmp<'_> {
    pub fn icmp_type(&self) -> Option<u8> {
        octets_at(self.header, 0).map(u8::from_be_bytes)
    }

    pub fn icmp_code(&self) -> Option<u8> {
        octets_at(self.header, 1).map(u8::from_be_bytes)
    }
}

impl fmt::Debug for Icmp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Icmp")
            .field("icmp_type", &self.icmp_type())
            .field("icmp_code", &self.icmp_code())
            .finish()
    }
}

pub fn icmp<'a>(input: &mut &'a [u8]) -> Icmp<'a> {
    Icmp {
        header: clipped(input, HEADER_LENGTH),
    }
}
