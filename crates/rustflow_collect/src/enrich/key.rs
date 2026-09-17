use std::net::IpAddr;

use ipnet::IpNet;

use crate::enrich::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Ip(IpAddr),
    Number(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Number,
}

impl KeyType {
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
