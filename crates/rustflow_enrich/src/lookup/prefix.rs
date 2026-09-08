use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use super::{Key, Lookup, Row};

#[derive(Default)]
pub struct PrefixTable {
    ipv4: PrefixMap<Ipv4Net, Row>,
    ipv6: PrefixMap<Ipv6Net, Row>,
}

impl PrefixTable {
    pub fn insert(&mut self, network: IpNet, row: Row) {
        match network {
            IpNet::V4(net) => {
                self.ipv4.insert(net.trunc(), row);
            }
            IpNet::V6(net) => {
                self.ipv6.insert(net.trunc(), row);
            }
        }
    }
}

impl Lookup for PrefixTable {
    fn lookup(&self, key: Key<'_>) -> Option<&Row> {
        let Key::Ip(ip) = key else {
            return None;
        };
        match ip {
            IpAddr::V4(ip) => self.ipv4.get_lpm(&Ipv4Net::from(ip)).map(|(_, row)| row),
            IpAddr::V6(ip) => self.ipv6.get_lpm(&Ipv6Net::from(ip)).map(|(_, row)| row),
        }
    }

    fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }
}
