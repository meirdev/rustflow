use std::fs;

use rustflow_enrich::*;

// A tiny original MMDB fixture: one IPv4 tree node, both /1 networks pointing
// to the same record. Encoding is limited to the types needed by these tests.
fn string(value: &str) -> Vec<u8> {
    assert!(value.len() < 29);
    let mut out = vec![0x40 | value.len() as u8];
    out.extend(value.as_bytes());
    out
}
fn number(kind: u8, value: u8) -> Vec<u8> {
    if kind < 8 {
        vec![(kind << 5) | 1, value]
    } else {
        vec![1, kind - 7, value]
    }
}
fn map(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut out = vec![0xe0 | entries.len() as u8];
    for (key, value) in entries {
        out.extend(string(key));
        out.extend(value);
    }
    out
}
fn fixture() -> Vec<u8> {
    let record = map(vec![
        ("country", map(vec![("iso_code", string("ZZ"))])),
        ("asn", number(6, 42)),
        ("enabled", vec![1, 7]), // extended type 14, boolean true
        ("empty", string("")),
    ]);
    let metadata = map(vec![
        ("binary_format_major_version", number(5, 2)),
        ("binary_format_minor_version", number(5, 0)),
        ("build_epoch", number(9, 1)),
        ("database_type", string("RustFlow-Test")),
        (
            "description",
            map(vec![("en", string("Synthetic test database"))]),
        ),
        ("ip_version", number(5, 4)),
        ("languages", vec![0, 4]), // extended type 11, empty array
        ("node_count", number(6, 1)),
        ("record_size", number(5, 24)),
    ]);
    let mut bytes = vec![0, 0, 17, 0, 0, 17];
    bytes.extend([0; 16]);
    bytes.extend(record);
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(metadata);
    bytes
}

#[test]
fn mmdb_networks_nested_fields_numbers_booleans_and_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.mmdb");
    fs::write(&path, fixture()).unwrap();
    let config = parse_enrich_arg(&format!(
        "type=prefix_lookup,source={},columns=country.iso_code|asn|enabled|missing.path|empty",
        path.display()
    ))
    .unwrap();
    let enrichment = Enrichment::new(config).unwrap();
    assert_eq!(enrichment.stats().loaded_rows, 2);
    for addr in ["1.2.3.4", "192.0.2.1"] {
        let out = enrichment.lookup(Key::Ip(addr.parse().unwrap())).unwrap();
        assert_eq!(out.get("country.iso_code").unwrap(), "ZZ");
        assert_eq!(out.get("asn").unwrap(), "42");
        assert_eq!(out.get("enabled").unwrap(), "true");
        assert!(out.get("missing.path").is_none());
        assert!(out.get("empty").is_none());
    }
    fs::write(&path, "corrupt mmdb").unwrap();
    assert!(enrichment.reload().is_err());
    assert_eq!(enrichment.stats().loaded_rows, 2);
}

// ---------------------------------------------------------------------------
// IPv6 search trees with an IPv4 subtree and MaxMind's alias nodes.

#[derive(Clone, Copy)]
enum Target {
    Empty,
    Node(usize),
    Data(usize),
}

/// A binary search tree built the way MaxMind's writers lay it out.
struct Tree {
    nodes: Vec<[Target; 2]>,
}

impl Tree {
    fn new() -> Self {
        Self {
            nodes: vec![[Target::Empty; 2]],
        }
    }

    /// The node reached after `bits`, creating internal nodes on the way.
    fn node_at(&mut self, bits: &[bool]) -> usize {
        let mut current = 0;
        for &bit in bits {
            let index = bit as usize;
            current = match self.nodes[current][index] {
                Target::Node(next) => next,
                Target::Empty => {
                    self.nodes.push([Target::Empty; 2]);
                    let next = self.nodes.len() - 1;
                    self.nodes[current][index] = Target::Node(next);
                    next
                }
                Target::Data(_) => panic!("path crosses a data node"),
            };
        }
        current
    }

    fn set(&mut self, bits: &[bool], target: Target) {
        let (last, prefix) = bits.split_last().unwrap();
        let node = self.node_at(prefix);
        self.nodes[node][*last as usize] = target;
    }

    /// 24-bit records: node index, `node_count` for empty, data offset past it.
    fn encode(&self) -> Vec<u8> {
        let node_count = self.nodes.len();
        let record = |target: Target| -> u32 {
            match target {
                Target::Empty => node_count as u32,
                Target::Node(n) => n as u32,
                Target::Data(offset) => (node_count + 16 + offset) as u32,
            }
        };
        self.nodes
            .iter()
            .flat_map(|[left, right]| {
                let mut out = record(*left).to_be_bytes()[1..].to_vec();
                out.extend_from_slice(&record(*right).to_be_bytes()[1..]);
                out
            })
            .collect()
    }
}

fn bits_of(ip: &str, prefix: usize) -> Vec<bool> {
    // IPv4 addresses live at the bottom of the IPv6 tree (`::a.b.c.d`), so
    // their prefix is counted from bit 96.
    let value: u128 = match ip.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(v4) => u128::from(u32::from(v4)),
        std::net::IpAddr::V6(v6) => u128::from(v6),
    };
    (0..prefix).map(|i| (value >> (127 - i)) & 1 == 1).collect()
}

/// Unsigned integer with the minimal payload (uint16/32/64 kinds).
fn uint(kind: u8, value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let payload = &bytes[bytes.len() - (64 - value.leading_zeros() as usize).div_ceil(8).max(1)..];
    let mut out = if kind < 8 {
        vec![(kind << 5) | payload.len() as u8]
    } else {
        vec![payload.len() as u8, kind - 7]
    };
    out.extend(payload);
    out
}

fn ipv6_database(tree: &Tree, records: &[Vec<u8>]) -> Vec<u8> {
    let metadata = map(vec![
        ("binary_format_major_version", uint(5, 2)),
        ("binary_format_minor_version", uint(5, 0)),
        ("build_epoch", uint(9, 1)),
        ("database_type", string("RustFlow-Test-v6")),
        (
            "description",
            map(vec![("en", string("Synthetic IPv6 tree"))]),
        ),
        ("ip_version", uint(5, 6)),
        ("languages", vec![0, 4]),
        ("node_count", uint(6, tree.nodes.len() as u64)),
        ("record_size", uint(5, 24)),
    ]);
    let mut bytes = tree.encode();
    bytes.extend([0; 16]);
    for record in records {
        bytes.extend(record);
    }
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(metadata);
    bytes
}

fn name_record(name: &str) -> Vec<u8> {
    map(vec![("name", string(name))])
}

/// What `maxminddb::Reader` itself answers, as the reference.
fn reader_name(reader: &maxminddb::Reader<Vec<u8>>, ip: &str) -> Option<String> {
    reader
        .lookup(ip.parse().unwrap())
        .unwrap()
        .decode_path::<String>(&[maxminddb::PathElement::Key("name")])
        .unwrap()
}

fn enrichment_for(path: &std::path::Path) -> Enrichment {
    let config = parse_enrich_arg(&format!(
        "type=prefix_lookup,source={},columns=name",
        path.display()
    ))
    .unwrap();
    Enrichment::new(config).unwrap()
}

fn enrichment_name(enrichment: &Enrichment, ip: &str) -> Option<String> {
    enrichment
        .lookup(Key::Ip(ip.parse().unwrap()))
        .map(|row| row.get("name").unwrap().to_owned())
}

#[test]
fn ipv6_tree_aliases_of_the_ipv4_subtree_resolve_like_the_reader() {
    let v4 = name_record("v4");
    let v6 = name_record("v6");

    let mut tree = Tree::new();
    let ipv4_root = tree.node_at(&bits_of("::", 96));
    // MaxMind's writers alias the IPv4 subtree at ::ffff:0:0/96 and 2002::/16.
    tree.set(&bits_of("::ffff:0:0", 96), Target::Node(ipv4_root));
    tree.set(&bits_of("2002::", 16), Target::Node(ipv4_root));
    // 1.0.0.0/8 inside the subtree, 2001:db8::/32 as a native IPv6 network.
    tree.set(&bits_of("1.0.0.0", 96 + 8), Target::Data(0));
    tree.set(&bits_of("2001:db8::", 32), Target::Data(v4.len()));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v6.mmdb");
    fs::write(&path, ipv6_database(&tree, &[v4, v6])).unwrap();

    let reader = maxminddb::Reader::open_readfile(&path).unwrap();
    let enrichment = enrichment_for(&path);
    // The reader's iteration skips the alias nodes: two networks, not four.
    assert_eq!(enrichment.stats().loaded_rows, 2);

    for ip in [
        "1.2.3.4",
        "::1.2.3.4",
        "::ffff:1.2.3.4",
        "2002:102:304::1",
        "9.9.9.9",
        "::ffff:9.9.9.9",
        "2002:909:909::",
        "2001:db8::1",
        "2001:db9::1",
    ] {
        assert_eq!(
            enrichment_name(&enrichment, ip),
            reader_name(&reader, ip),
            "{ip}"
        );
    }
    assert_eq!(
        enrichment_name(&enrichment, "::ffff:1.2.3.4").as_deref(),
        Some("v4")
    );
    assert_eq!(
        enrichment_name(&enrichment, "2002:102:304::1").as_deref(),
        Some("v4")
    );
    assert_eq!(
        enrichment_name(&enrichment, "2001:db8::1").as_deref(),
        Some("v6")
    );
    assert_eq!(enrichment_name(&enrichment, "::ffff:9.9.9.9"), None);
}

#[test]
fn ipv6_record_above_the_ipv4_subtree_applies_to_ipv4_lookups() {
    // No IPv4 subtree: a record on ::/64 is what the reader returns for
    // every IPv4 address (and for the alias ranges below it).
    let mut tree = Tree::new();
    tree.set(&bits_of("::", 64), Target::Data(0));
    tree.set(&bits_of("2001:db8::", 32), Target::Data(0));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("above.mmdb");
    fs::write(&path, ipv6_database(&tree, &[name_record("above")])).unwrap();

    let reader = maxminddb::Reader::open_readfile(&path).unwrap();
    let enrichment = enrichment_for(&path);
    assert!(enrichment.stats().loaded_rows >= 1);

    for ip in [
        "1.2.3.4",
        "::1.2.3.4",
        "::ffff:1.2.3.4",
        "2002:102:304::1",
        "2001:db8::1",
        "2001:db9::1",
        "fe80::1",
    ] {
        assert_eq!(
            enrichment_name(&enrichment, ip),
            reader_name(&reader, ip),
            "{ip}"
        );
    }
    assert_eq!(
        enrichment_name(&enrichment, "1.2.3.4").as_deref(),
        Some("above")
    );
    assert_eq!(enrichment_name(&enrichment, "fe80::1"), None);
}
