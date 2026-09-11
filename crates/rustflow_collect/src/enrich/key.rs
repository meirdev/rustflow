use std::borrow::Cow;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::enrich::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key<'a> {
    Ip(IpAddr),
    Number(u64),
    Text(Cow<'a, str>),
}

impl Key<'_> {
    pub fn into_owned(self) -> Key<'static> {
        match self {
            Self::Ip(ip) => Key::Ip(ip),
            Self::Number(number) => Key::Number(number),
            Self::Text(text) => Key::Text(Cow::Owned(text.into_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Number,
    Text,
}

impl KeyType {
    pub fn parse<'a>(self, raw: &'a str) -> Result<Key<'a>> {
        match self {
            Self::Ip => raw
                .parse()
                .map(Key::Ip)
                .map_err(|_| Error::Data(format!("Invalid IP key '{raw}'"))),
            Self::Number => raw
                .parse()
                .map(Key::Number)
                .map_err(|_| Error::Data(format!("Invalid unsigned numeric key '{raw}'"))),
            Self::Text => Ok(Key::Text(Cow::Borrowed(raw))),
        }
    }
}

pub fn parse_prefix(raw: &str) -> Result<IpNet> {
    raw.parse()
        .map_err(|_| Error::Data(format!("Invalid prefix '{raw}'")))
}
