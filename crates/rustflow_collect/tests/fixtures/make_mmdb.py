# /// script
# requires-python = ">=3.12"
# dependencies = ["mmdb-writer>=0.2"]
# ///
"""Build test.mmdb: an IPv6 tree with typed, nested records, the way MaxMind's
own databases are laid out. Run with `uv run make_mmdb.py`."""
from mmdb_writer import MMDBWriter
from netaddr import IPSet

RECORDS = [
    (
        "1.0.0.0/8",
        {
            "country": {"iso_code": "AU", "names": {"en": "Australia"}},
            "asn": 13335,
            "anycast": True,
            "empty": "",
        },
    ),
    ("10.0.0.0/8", {"country": {"iso_code": "ZZ"}}),
    ("10.1.0.0/16", {"country": {"iso_code": "ZY"}, "asn": 64512}),
    ("2001:db8::/32", {"country": {"iso_code": "V6"}, "tags": ["a", "b"]}),
]

writer = MMDBWriter(
    ip_version=6,
    ipv4_compatible=True,
    database_type="RustFlow-Test",
    description="Synthetic rustflow_enrich fixture",
)
for network, record in RECORDS:
    writer.insert_network(IPSet([network]), record)
writer.to_db_file("test.mmdb")
