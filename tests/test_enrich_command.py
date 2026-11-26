"""Enrichment from a command: a script that prints a CSV source must enrich
exactly like the file itself, and a script that fails must stop the collector.
"""

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

LOOKUP = """
key_columns = ["number"]

[[enrich.lookup]]
keys = ["proto"]
fields = [{ column = "name", name = "proto_name" }]
"""


@pytest.fixture
def script(tmp_path) -> Callable[[str], Path]:
    """Writes an executable shell script with the given body."""
    path = tmp_path / "source.sh"

    def write(body: str) -> Path:
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
        return path

    return write


@pytest.fixture
def config(tmp_path) -> Callable[[str], list[str]]:
    """The flags for a configuration enriching from the given origin."""

    def write(origin: str) -> list[str]:
        path = tmp_path / "rustflow.toml"
        path.write_text(f'[[enrich]]\ntype = "exact"\n{origin}\n{LOOKUP}')
        return ["--format", "common", "--config", str(path)]

    return write


@pytest.fixture
def pcap(pcap_dir) -> Path:
    return pcap_dir / "netflow_v5_sanity.pcap"


def test_command_enriches_like_the_file(collect, script, config, pcap):
    protocols = pcap.parent.parent / "csv" / "protocols.csv"

    from_file = collect(pcap, "netflow", *config(f'source = "{protocols}"'))
    command = script(f"cat {protocols}")
    from_command = collect(pcap, "netflow", *config(f'command = "{command}"'))

    assert b'"proto_name":"tcp"' in from_file
    assert from_command == from_file


@pytest.mark.parametrize(
    "body,extra,message",
    [
        ("echo number,name; echo 6,tcp; exit 1", "", "Command failed: exit status: 1"),
        ("echo number,name", "", "Command printed no rows"),
        ("sleep 30", 'timeout = "1s"', "Command timed out after 1s"),
    ],
    ids=["exit-status", "no-rows", "timeout"],
)
def test_failed_command_stops_the_collector(
    collect, script, config, pcap, body, extra, message
):
    origin = f'command = "{script(body)}"\n{extra}'

    with pytest.raises(subprocess.CalledProcessError) as error:
        collect(pcap, "netflow", *config(origin))

    assert message in error.value.stderr.decode()
    assert error.value.stdout == b""
