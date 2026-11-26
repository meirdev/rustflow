"""The configuration file: its paths follow it, a flag wins over it, and a
key it does not have is an error.
"""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def pcap(pcap_dir: Path) -> Path:
    return pcap_dir / "ipfix_sanity.pcap"


def test_relative_paths_are_relative_to_the_file(
    collect, enrich_config, pcap, snapshot_dir, tmp_path
):
    for sources in ("mmdb", "csv"):
        shutil.copytree(enrich_config.parent / sources, tmp_path / sources)
    moved = shutil.copy(enrich_config, tmp_path)

    actual = collect(pcap, "netflow", "--config", moved, "-f", "common")

    assert actual == (snapshot_dir / "ipfix.enriched.ndjson").read_bytes()


def test_a_flag_wins_over_the_file(collect, pcap, tmp_path):
    config = tmp_path / "rustflow.toml"
    config.write_text('[output]\nformat = "common"\nserialization = "ndjson"\n')

    actual = collect(
        pcap, "netflow", "--config", str(config), "-s", "csv", "--fields", "bytes"
    )

    assert actual.splitlines()[0] == b"bytes"


def test_an_unknown_key_is_an_error(collect, pcap, tmp_path):
    config = tmp_path / "rustflow.toml"
    config.write_text('[output]\nserialisation = "csv"\n')

    with pytest.raises(subprocess.CalledProcessError) as error:
        collect(pcap, "netflow", "--config", str(config))

    assert "unknown field `serialisation`" in error.value.stderr.decode()
