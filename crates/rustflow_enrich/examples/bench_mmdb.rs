//! Compare `MmdbSource` (reader tree walk + decode per lookup) with the bare
//! `maxminddb` reader and with materializing all networks into a prefix trie.
//!
//!     cargo run --release -p rustflow_enrich --example bench_mmdb --
//! GeoLite2-Country.mmdb [lookups]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use ipnet::IpNet;
use maxminddb::PathElement;
use prefix_trie::PrefixMap;
use rustflow_enrich::{Enrichment, Key, MmdbSource, Schema, Source, parse_enrich_arg};

/// The materialized alternative: every network with data, in a prefix trie
/// keyed the way `PrefixTable` does it (IPv4 and IPv6 apart), with alias
/// ranges resolved before the probe.
struct Trie {
    v4: PrefixMap<ipnet::Ipv4Net, String>,
    v6: PrefixMap<ipnet::Ipv6Net, String>,
}

impl Trie {
    fn build(reader: &maxminddb::Reader<Vec<u8>>, path: &[PathElement<'_>]) -> Self {
        let mut trie = Trie {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        };
        for result in reader.networks(Default::default()).unwrap() {
            let r = result.unwrap();
            let Some(value) = r.decode_path::<String>(path).unwrap() else {
                continue;
            };
            let net = r.network().unwrap();
            match IpNet::new(net.ip(), net.prefix()).unwrap() {
                IpNet::V4(n) => {
                    trie.v4.insert(n, value);
                }
                IpNet::V6(n) => {
                    trie.v6.insert(n, value);
                }
            }
        }
        trie
    }

    fn get(&self, ip: IpAddr) -> Option<&str> {
        let v4 = |ip: Ipv4Addr| {
            self.v4
                .get_lpm(&ipnet::Ipv4Net::from(ip))
                .map(|(_, v)| v.as_str())
        };
        let v6 = |ip: Ipv6Addr| {
            self.v6
                .get_lpm(&ipnet::Ipv6Net::from(ip))
                .map(|(_, v)| v.as_str())
        };
        match ip {
            IpAddr::V4(a) => v4(a).or_else(|| v6(a.to_ipv6_compatible())),
            IpAddr::V6(a) => match a.segments() {
                [0, 0, 0, 0, 0, 0 | 0xffff, h, l] | [0x2002, h, l, ..] => {
                    v4(Ipv4Addr::from((u32::from(h) << 16) | u32::from(l))).or_else(|| v6(a))
                }
                _ => v6(a),
            },
        }
    }
}

const COLUMN: &str = "country.iso_code";

fn rss_kib() -> u64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// xorshift64*, deterministic and dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

struct Timing {
    ns_per_lookup: f64,
    hits: usize,
}

fn bench(
    label: &str,
    addrs: &[IpAddr],
    lookups: usize,
    mut f: impl FnMut(IpAddr) -> bool,
) -> Timing {
    // Warm up on a slice, then time.
    for ip in addrs.iter().take(10_000) {
        black_box(f(*ip));
    }
    let start = Instant::now();
    let mut hits = 0;
    for i in 0..lookups {
        if black_box(f(addrs[i % addrs.len()])) {
            hits += 1;
        }
    }
    let ns = start.elapsed().as_nanos() as f64 / lookups as f64;
    println!(
        "  {label:<44} {ns:8.1} ns/lookup  {:6.2} M/s  hits {:.1}%",
        1000.0 / ns,
        100.0 * hits as f64 / lookups as f64
    );
    Timing {
        ns_per_lookup: ns,
        hits,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path: PathBuf = args
        .next()
        .expect("usage: bench_mmdb <db.mmdb> [lookups]")
        .into();
    let lookups: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(2_000_000);

    // --- Load both ways -----------------------------------------------------
    let rss0 = rss_kib();
    let t = Instant::now();
    let reader = maxminddb::Reader::open_readfile(&path).unwrap();
    let reader_load = t.elapsed();
    let rss1 = rss_kib();

    let schema = Schema::new([COLUMN]);
    let t = Instant::now();
    let lookup = MmdbSource::open(&path, &schema).unwrap();
    let lookup_load = t.elapsed();
    let rss2 = rss_kib();

    let iso_path = [PathElement::Key("country"), PathElement::Key("iso_code")];
    let t = Instant::now();
    let table = Trie::build(&reader, &iso_path);
    let table_load = t.elapsed();
    let rss3 = rss_kib();

    // The engine now uses MmdbSource; measured too for the API overhead.
    let config = parse_enrich_arg(&format!(
        "type=prefix_lookup,source={},columns={COLUMN}",
        path.display()
    ))
    .unwrap();
    let enrichment = Enrichment::new(config).unwrap();

    println!(
        "database: {} ({} KiB on disk)",
        path.display(),
        std::fs::metadata(&path).unwrap().len() / 1024
    );
    println!(
        "maxminddb::Reader  load {:>8.1?}   RSS +{:>7} KiB",
        reader_load,
        rss1 - rss0
    );
    println!(
        "MmdbSource         load {:>8.1?}   RSS +{:>7} KiB   networks {}",
        lookup_load,
        rss2 - rss1,
        lookup.len()
    );
    println!(
        "prefix trie        load {:>8.1?}   RSS +{:>7} KiB   rows {}",
        table_load,
        rss3 - rss2,
        table.v4.len() + table.v6.len()
    );

    // --- Address sets --------------------------------------------------------
    let mut hits: Vec<IpAddr> = Vec::new();
    for result in reader.networks(Default::default()).unwrap() {
        let r = result.unwrap();
        if r.has_data() {
            hits.push(r.network().unwrap().ip());
        }
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    // Shuffle so consecutive lookups do not share tree paths.
    for i in (1..hits.len()).rev() {
        hits.swap(i, (rng.next() as usize) % (i + 1));
    }
    let random_v4: Vec<IpAddr> = (0..1_000_000)
        .map(|_| IpAddr::V4(Ipv4Addr::from(rng.next() as u32)))
        .collect();
    let random_v6: Vec<IpAddr> = (0..1_000_000)
        .map(|_| {
            IpAddr::V6(Ipv6Addr::from(
                (0x2000u128 << 112) | (rng.next() as u128 >> 3 << 64) | rng.next() as u128,
            ))
        })
        .collect();
    let mapped_v4: Vec<IpAddr> = random_v4
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 => *v6,
        })
        .collect();
    println!(
        "addresses: {} network hits, 1M random IPv4, 1M random IPv6 (2000::/3), 1M IPv4-mapped\n",
        hits.len()
    );

    // --- Correctness: both must agree on every hit and on random samples -----
    let snapshot = enrichment.snapshot();
    let mut mismatches = 0;
    for ip in hits
        .iter()
        .chain(random_v4.iter().take(200_000))
        .chain(random_v6.iter().take(200_000))
        .chain(mapped_v4.iter().take(200_000))
    {
        let via_lookup = lookup
            .lookup(Key::Ip(*ip))
            .and_then(|row| row.get(COLUMN).map(str::to_owned));
        let via_table = table.get(*ip).map(str::to_owned);
        let theirs: Option<String> = reader.lookup(*ip).unwrap().decode_path(&iso_path).unwrap();
        if via_lookup != theirs || via_table != theirs {
            mismatches += 1;
            if mismatches <= 5 {
                println!(
                    "MISMATCH {ip}: lookup={via_lookup:?} table={via_table:?} reader={theirs:?}"
                );
            }
        }
    }
    println!(
        "correctness: {mismatches} mismatches out of {} compared\n",
        hits.len() + 600_000
    );

    // --- Throughput ----------------------------------------------------------
    for (name, addrs) in [
        ("network hits", &hits),
        ("random IPv4", &random_v4),
        ("random IPv6", &random_v6),
        ("IPv4-mapped IPv6", &mapped_v4),
    ] {
        println!("{name}:");
        let a = bench("MmdbSource (reader + decode)", addrs, lookups, |ip| {
            lookup
                .lookup(Key::Ip(ip))
                .is_some_and(|row| row.get(COLUMN).is_some())
        });
        let b = bench("materialized prefix trie", addrs, lookups, |ip| {
            table.get(ip).is_some()
        });
        bench("Enrichment snapshot (MmdbSource)", addrs, lookups, |ip| {
            snapshot
                .lookup(Key::Ip(ip))
                .is_some_and(|row| row.get(COLUMN).is_some())
        });
        bench("Enrichment::lookup (MmdbSource)", addrs, lookups, |ip| {
            enrichment.lookup(Key::Ip(ip)).is_some()
        });
        bench("maxminddb lookup only (tree walk)", addrs, lookups, |ip| {
            reader.lookup(ip).unwrap().has_data()
        });
        let c = bench(
            "maxminddb lookup + decode_path::<&str>",
            addrs,
            lookups,
            |ip| {
                reader
                    .lookup(ip)
                    .unwrap()
                    .decode_path::<&str>(&iso_path)
                    .unwrap()
                    .is_some()
            },
        );
        bench(
            "maxminddb lookup + decode_path::<String>",
            addrs,
            lookups,
            |ip| {
                reader
                    .lookup(ip)
                    .unwrap()
                    .decode_path::<String>(&iso_path)
                    .unwrap()
                    .is_some()
            },
        );
        println!(
            "  -> MmdbSource is {:.1}x the speed of reader+decode, {:.1}x {} than the trie\n",
            c.ns_per_lookup / a.ns_per_lookup,
            (b.ns_per_lookup / a.ns_per_lookup).max(a.ns_per_lookup / b.ns_per_lookup),
            if a.ns_per_lookup <= b.ns_per_lookup {
                "faster"
            } else {
                "slower"
            }
        );
        assert_eq!(a.hits, c.hits, "hit counts differ on {name}");
        assert_eq!(a.hits, b.hits, "hit counts differ on {name}");
    }
}
