use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use super::Source;
use crate::enrich::key::Key;
use crate::enrich::row::Row;

#[derive(Default)]
pub struct PrefixTable {
    ipv4: PrefixMap<Ipv4Net, Row>,
    ipv6: PrefixMap<Ipv6Net, Row>,
}

impl PrefixTable {
    pub fn insert(&mut self, net: IpNet, row: Row) {
        match net {
            IpNet::V4(net) => {
                self.ipv4.insert(net.trunc(), row);
            }
            IpNet::V6(net) => {
                self.ipv6.insert(net.trunc(), row);
            }
        }
    }
}

impl Source for PrefixTable {
    fn lookup(&self, key: Key) -> Option<Row> {
        let row = match key {
            Key::Ip(IpAddr::V4(ip)) => self.ipv4.get_lpm(&Ipv4Net::from(ip)).map(|(_, row)| row),
            Key::Ip(IpAddr::V6(ip)) => self.ipv6.get_lpm(&Ipv6Net::from(ip)).map(|(_, row)| row),
            _ => None,
        };
        row.cloned()
    }

    fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }
}
