use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::{Error, Result};

/// A typed lookup key. Text can borrow for allocation-free lookups or own its
/// contents for storage. Prefix tables match only `Ip`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key<'a> {
    Ip(IpAddr),
    Number(u64),
    Text(Cow<'a, str>),
}

impl Key<'_> {
    /// Own borrowed text so the key can outlive its source buffer.
    pub fn into_owned(self) -> Key<'static> {
        match self {
            Self::Ip(ip) => Key::Ip(ip),
            Self::Number(number) => Key::Number(number),
            Self::Text(text) => Key::Text(Cow::Owned(text.into_owned())),
        }
    }
}

/// How to parse a textual source key into a [`Key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Number,
    Text,
}

impl KeyType {
    /// Parse a textual key of this type. Text keys borrow `raw` unchanged.
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

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ip" => Ok(Self::Ip),
            "number" => Ok(Self::Number),
            "text" => Ok(Self::Text),
            other => Err(Error::Config(format!("Unknown key_type '{other}'"))),
        }
    }
}

/// Parse a textual network prefix for a [`PrefixTable`](super::PrefixTable).
pub fn parse_prefix(raw: &str) -> Result<IpNet> {
    raw.parse()
        .map_err(|_| Error::Data(format!("Invalid prefix '{raw}'")))
}
