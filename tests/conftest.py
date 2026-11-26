"""Shared fixtures: the rustflow binary, the fixture directories, the
configuration file that enriches from the fixture sources, and a helper that replays a
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
def enrich_config() -> Path:
    return FIXTURES_DIR / "enrich.toml"


@pytest.fixture
def collect(rustflow_bin: Path) -> Callable[..., bytes]:
    def run(
        pcap: Path, protocol: str, *args: str, output: Path | None = None
    ) -> bytes:
        cmd = [rustflow_bin, "collect", "--input", f"{protocol}+pcap://{pcap}"]
        cmd += args
        if output is not None:
            cmd += ["--output", output]
        result = subprocess.run(cmd, capture_output=True, check=True, timeout=30)
        return output.read_bytes() if output is not None else result.stdout

    return run
