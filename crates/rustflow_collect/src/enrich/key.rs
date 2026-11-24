use std::net::IpAddr;

use ipnet::IpNet;
use rustflow_core::information_element::DataType;
use rustflow_core::value::Value;

use crate::enrich::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Ip(IpAddr),
    Number(u64),
}

impl Key {
    /// A record's value as a key: an address, or an unsigned number.
    pub fn of_record(value: &Value) -> Option<Self> {
        Some(match value {
            Value::Ipv4Address(address) => Self::Ip((*address).into()),
            Value::Ipv6Address(address) => Self::Ip((*address).into()),
            value => Self::Number(value.as_u64()?),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Number,
}

impl KeyType {
    /// The type of the keys that values of `data_type` make; `None` when
    /// they cannot be keys.
    pub fn of(data_type: DataType) -> Option<Self> {
        use DataType as D;
        match data_type {
            D::Ipv4Address | D::Ipv6Address => Some(Self::Ip),
            D::Unsigned8 | D::Unsigned16 | D::Unsigned32 | D::Unsigned64 => Some(Self::Number),
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
