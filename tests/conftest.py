"""Shared fixtures: the rustflow binary, the fixture directories, the
`--enrich` arguments for the fixture sources, and a helper that replays a
pcap through `rustflow collect`.

Build first (`cargo build --release`), or point `RUSTFLOW_BIN` at a binary.
"""

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_DIR = TESTS_DIR.parent
FIXTURES_DIR = TESTS_DIR / "fixtures"


@pytest.fixture(scope="session")
def rustflow_bin() -> Path:
    if env := os.environ.get("RUSTFLOW_BIN"):
        candidates = [Path(env)]
    else:
        candidates = [
            REPO_DIR / "target" / profile / "rustflow"
            for profile in ("release", "debug")
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    pytest.fail(
        "no rustflow binary at "
        + ", ".join(map(str, candidates))
        + "; run `cargo build --release` or set RUSTFLOW_BIN"
    )


@pytest.fixture(scope="session")
def pcap_dir() -> Path:
    return FIXTURES_DIR / "pcap"


@pytest.fixture(scope="session")
def snapshot_dir() -> Path:
    return FIXTURES_DIR / "snapshots"


@pytest.fixture(scope="session")
def enrich_args() -> list[str]:
    mmdb = FIXTURES_DIR / "mmdb"
    csv = FIXTURES_DIR / "csv"
    sources = [
        f"type=prefix_lookup,source={mmdb}/country.mmdb,fields=src_addr@country.iso_code:src_country;dst_addr@country.iso_code:dst_country",
        f"type=prefix_lookup,source={mmdb}/asn.mmdb,fields=src_addr@autonomous_system_number:src_asn|autonomous_system_organization:src_as_org;dst_addr@autonomous_system_number:dst_asn|autonomous_system_organization:dst_as_org",
        f"type=prefix_lookup,source={csv}/networks.csv,key_column=prefix,fields=src_addr@asn:csv_src_asn|country:csv_src_country;next_hop@org:next_hop_org",
        f"type=exact,source={csv}/protocols.csv,key_column=number,fields=proto@name:proto_name",
    ]
    return [arg for source in sources for arg in ("--enrich", source)]


@pytest.fixture
def collect(rustflow_bin: Path) -> Callable[..., bytes]:
    """Runs `rustflow collect --pcap <pcap> <args...>` and returns what it
    wrote: stdout, or the contents of `output` when one is given (Parquet
    needs a file)."""

    def run(pcap: Path, *args: str, output: Path | None = None) -> bytes:
        cmd = [rustflow_bin, "collect", "--pcap", pcap, *args]
        if output is not None:
            cmd += ["--output", output]
        result = subprocess.run(cmd, capture_output=True, check=True, timeout=30)
        return output.read_bytes() if output is not None else result.stdout

    return run
