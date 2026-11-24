use std::net::IpAddr;

use ipnet::IpNet;

use crate::enrich::{Error, Result};
use crate::field::{Kind, Scalar};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Ip(IpAddr),
    Number(u64),
}

impl Key {
    /// A column's value as a key: an address, or an unsigned number.
    pub fn of(value: Scalar<'_>) -> Option<Self> {
        match value {
            Scalar::Address(address) => Some(Self::Ip(address)),
            Scalar::Unsigned(number) => Some(Self::Number(number)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Number,
}

impl KeyType {
    /// The type of the keys that the values of a column of `kind` make;
    /// `None` when they cannot be keys.
    pub fn of(kind: Kind) -> Option<Self> {
        match kind {
            Kind::Address => Some(Self::Ip),
            Kind::U8 | Kind::U16 | Kind::U32 | Kind::U64 => Some(Self::Number),
            _ => None,
        }
    }

    pub fn parse(self, raw: &str) -> Result<Key> {
        match self {
            Self::Ip => raw
                .parse()
                .map(Key::Ip)
                .map_err(|_| Error::Data(format!("Invalid IP key '{raw}'"))),
            Self::Number => raw
                .parse()
                .map(Key::Number)
                .map_err(|_| Error::Data(format!("Invalid unsigned numeric key '{raw}'"))),
        }
    }
}

pub fn parse_prefix(raw: &str) -> Result<IpNet> {
    raw.parse()
        .map_err(|_| Error::Data(format!("Invalid prefix '{raw}'")))
}
