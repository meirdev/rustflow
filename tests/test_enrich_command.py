"""Enrichment from a command: a script that prints a CSV source must enrich
exactly like the file itself, and a script that fails must stop the collector.
"""

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

FIELDS = "key_column=number,fields=proto@name:proto_name"


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
def args(pcap_dir) -> tuple[Path, tuple[str, ...]]:
    pcap = pcap_dir / "netflow_v5_sanity.pcap"
    return pcap, ("--flow-type", "netflow", "--format", "common")


def test_command_enriches_like_the_file(collect, script, args):
    pcap, flags = args
    protocols = pcap.parent.parent / "csv" / "protocols.csv"

    from_file = collect(
        pcap, *flags, "--enrich", f"type=exact,source={protocols},{FIELDS}"
    )
    from_command = collect(
        pcap,
        *flags,
        "--enrich",
        f"type=exact,command={script(f'cat {protocols}')},{FIELDS}",
    )

    assert b'"proto_name":"tcp"' in from_file
    assert from_command == from_file


@pytest.mark.parametrize(
    "body,extra,message",
    [
        ("echo number,name; echo 6,tcp; exit 1", "", "Command failed: exit status: 1"),
        ("echo number,name", "", "Command printed no rows"),
        ("sleep 30", ",timeout=1s", "Command timed out after 1s"),
    ],
    ids=["exit-status", "no-rows", "timeout"],
)
def test_failed_command_stops_the_collector(
    collect, script, args, body, extra, message
):
    pcap, flags = args

    with pytest.raises(subprocess.CalledProcessError) as error:
        collect(
            pcap,
            *flags,
            "--enrich",
            f"type=exact,command={script(body)}{extra},{FIELDS}",
        )

    assert message in error.value.stderr.decode()
    assert error.value.stdout == b""
