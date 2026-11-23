"""Protocol conformance: replay each capture under `fixtures/conformance/`
and compare what rustflow makes of it with the expected result beside it:
the packets, as `--format raw` prints them, and the flows, as `--format
common` does.

The expected results are written from the specifications, not recorded
from rustflow; `fixtures/conformance/INDEX.md` lists the cases. Each
capture is also read by Wireshark, where it is installed, to check the
capture itself.
"""

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

CASES_DIR = Path(__file__).resolve().parent / "fixtures" / "conformance"

# directory -> the `collect --input` protocol that reads it
INPUT = {
    "netflow_v5": "netflow",
    "netflow_v9": "netflow",
    "ipfix": "netflow",
    "sflow_v5": "sflow",
    "vendors": "netflow",
}


@dataclass(frozen=True)
class Fixture:
    protocol: str
    name: str
    pcap: Path
    document: dict

    @property
    def id(self) -> str:
        return f"{self.protocol}/{self.name}"


FIXTURES = [
    Fixture(path.parent.name, path.stem, path.with_suffix(".pcap"), json.loads(path.read_text()))
    for path in sorted(CASES_DIR.glob("*/*.json"))
]


def collected(rustflow_bin: Path, fixture: Fixture, format: str) -> list[dict]:
    url = f"{INPUT[fixture.protocol]}+pcap://{fixture.pcap}"
    result = subprocess.run(
        [rustflow_bin, "collect", "--input", url, "--format", format],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return [json.loads(line) for line in result.stdout.splitlines()]


def differences(expected, actual, path: str = "$") -> list[str]:
    """Where two JSON values differ, one line per difference."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in expected.keys() | actual.keys():
            if key not in actual:
                out.append(f"{path}.{key}: missing, expected {expected[key]!r}")
            elif key not in expected:
                out.append(f"{path}.{key}: unexpected {actual[key]!r}")
            else:
                out += differences(expected[key], actual[key], f"{path}.{key}")
        return sorted(out)
    if isinstance(expected, list) and isinstance(actual, list):
        out = []
        if len(expected) != len(actual):
            out.append(f"{path}: {len(actual)} items, expected {len(expected)}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            out += differences(e, a, f"{path}[{i}]")
        return out
    # 1 and 1.0, or True and 1, are different JSON values.
    if type(expected) is not type(actual) or expected != actual:
        return [f"{path}: {actual!r}, expected {expected!r}"]
    return []


def tshark_fields(pcap: Path, fields: list[str]) -> dict[str, list[str]]:
    """Every value each field takes in the capture, in order."""
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t"]
    cmd += ["-E", "occurrence=a", "-E", "aggregator=\x1f"]
    for name in fields:
        cmd += ["-e", name]
    result = subprocess.run(cmd, capture_output=True, check=True, timeout=60, text=True)
    values: dict[str, list[str]] = {name: [] for name in fields}
    for line in result.stdout.split("\n"):
        for name, column in zip(fields, line.split("\t")):
            values[name] += [value for value in column.split("\x1f") if value]
    return values


def tshark_problems(pcap: Path) -> str:
    """The frames Wireshark finds malformed."""
    result = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "_ws.malformed"],
        capture_output=True,
        check=True,
        timeout=60,
        text=True,
    )
    return result.stdout


def params():
    for fixture in FIXTURES:
        deviation = fixture.document.get("deviation")
        marks = [pytest.mark.xfail(reason=deviation, strict=True)] if deviation else []
        yield pytest.param(fixture, id=fixture.id, marks=marks)


@pytest.mark.parametrize("fixture", params())
def test_rustflow_reads_what_the_specification_says(rustflow_bin, fixture):
    problems = differences(fixture.document["expected"], collected(rustflow_bin, fixture, "raw"))
    problems += differences(fixture.document["flows"], collected(rustflow_bin, fixture, "common"), "flows")
    assert not problems, "\n".join(problems)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is not installed")
@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.id for f in FIXTURES])
def test_wireshark_reads_the_capture_the_same_way(fixture):
    problems = []
    if expected := fixture.document.get("tshark", {}):
        problems += differences(expected, tshark_fields(fixture.pcap, list(expected)), "tshark")
    if fixture.document.get("clean", True) and (found := tshark_problems(fixture.pcap)):
        problems.append(f"tshark finds malformed frames:\n{found}")
    assert not problems, "\n".join(problems)
