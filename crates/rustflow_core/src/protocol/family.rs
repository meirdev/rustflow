use std::fmt;

use crate::bytes::Reader;
use crate::protocol::ParseError;

/// What a collector listens for on one port. NetFlow and IPFIX share the
/// version field at the start of a datagram, so one port serves all three;
/// sFlow has a port of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Netflow,
    Sflow,
}

impl Family {
    /// The lowercase name, `netflow` or `sflow`, that logs and metric labels
    /// use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Netflow => "netflow",
            Self::Sflow => "sflow",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
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
    /// The lowercase name, such as `netflow_v9`, that logs and metric labels
    /// use.
    pub fn name(self) -> &'static str {
        match self {
            Self::NetflowV5 => "netflow_v5",
            Self::NetflowV9 => "netflow_v9",
            Self::Ipfix => "ipfix",
            Self::SflowV5 => "sflow_v5",
        }
    }

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

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Truncated;

    #[test]
    fn names_are_snake_case() {
        assert_eq!(Protocol::NetflowV9.name(), "netflow_v9");
        assert_eq!(Protocol::SflowV5.to_string(), "sflow_v5");
        assert_eq!(Family::Netflow.name(), "netflow");
        assert_eq!(Family::Sflow.to_string(), "sflow");
    }

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
