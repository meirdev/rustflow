use rustflow_bytes::Reader;

use crate::ParseError;

/// A flow protocol, told from a datagram's first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

impl Protocol {
    /// The protocol of `datagram`: NetFlow and IPFIX put their version in
    /// the first two bytes, sFlow in the first four, so its first two are
    /// zero.
    pub fn of(datagram: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(datagram);
        let version = r.u16()?;
        match version {
            5 => Ok(Self::NetflowV5),
            9 => Ok(Self::NetflowV9),
            10 => Ok(Self::Ipfix),
            0 => match r.u16()? {
                5 => Ok(Self::SflowV5),
                low => Err(ParseError::Version(low.into())),
            },
            other => Err(ParseError::Version(other.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use rustflow_bytes::Truncated;

    use super::*;

    #[test]
    fn protocols_are_told_by_their_version_bytes() {
        assert_eq!(Protocol::of(&[0, 5, 0, 1]), Ok(Protocol::NetflowV5));
        assert_eq!(Protocol::of(&[0, 9, 0, 1]), Ok(Protocol::NetflowV9));
        assert_eq!(Protocol::of(&[0, 10, 0, 16]), Ok(Protocol::Ipfix));
        assert_eq!(Protocol::of(&[0, 0, 0, 5]), Ok(Protocol::SflowV5));
        assert_eq!(Protocol::of(&[0, 0, 0, 4]), Err(ParseError::Version(4)));
        assert_eq!(Protocol::of(&[0, 1, 0, 0]), Err(ParseError::Version(1)));
        assert_eq!(
            Protocol::of(&[0, 0, 0]),
            Err(ParseError::Truncated(Truncated {
                requested: 2,
                available: 1,
            }))
        );
    }
}
