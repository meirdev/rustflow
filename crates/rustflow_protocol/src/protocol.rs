use rustflow_bytes::Reader;

use crate::ParseError;

/// What a collector listens for on one port. NetFlow and IPFIX share the
/// version field at the start of a datagram, so one port serves all three;
/// sFlow has a port of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Netflow,
    Sflow,
}

/// A flow protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    NetflowV5,
    NetflowV9,
    Ipfix,
    SflowV5,
}

impl Protocol {
    /// The protocol of a datagram of `family`, by the version at its start:
    /// two bytes for NetFlow and IPFIX, four for sFlow.
    pub fn of(family: Family, datagram: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(datagram);
        match family {
            Family::Netflow => match r.u16()? {
                5 => Ok(Self::NetflowV5),
                9 => Ok(Self::NetflowV9),
                10 => Ok(Self::Ipfix),
                other => Err(ParseError::Version(other.into())),
            },
            Family::Sflow => match r.u32()? {
                5 => Ok(Self::SflowV5),
                other => Err(ParseError::Version(other)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rustflow_bytes::Truncated;

    use super::*;

    #[test]
    fn protocols_are_told_by_their_version_within_their_family() {
        let netflow = |datagram| Protocol::of(Family::Netflow, datagram);
        assert_eq!(netflow(&[0, 5, 0, 1]), Ok(Protocol::NetflowV5));
        assert_eq!(netflow(&[0, 9, 0, 1]), Ok(Protocol::NetflowV9));
        assert_eq!(netflow(&[0, 10, 0, 16]), Ok(Protocol::Ipfix));
        assert_eq!(netflow(&[0, 0, 0, 5]), Err(ParseError::Version(0)));
        assert_eq!(netflow(&[0, 1, 0, 0]), Err(ParseError::Version(1)));

        let sflow = |datagram| Protocol::of(Family::Sflow, datagram);
        assert_eq!(sflow(&[0, 0, 0, 5]), Ok(Protocol::SflowV5));
        assert_eq!(sflow(&[0, 0, 0, 4]), Err(ParseError::Version(4)));
        assert_eq!(sflow(&[0, 5, 0, 1]), Err(ParseError::Version(0x5_0001)));
        assert_eq!(
            sflow(&[0, 0, 0]),
            Err(ParseError::Truncated(Truncated {
                requested: 4,
                available: 3,
            }))
        );
    }
}
