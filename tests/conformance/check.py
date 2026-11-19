"""Checks the conformance captures: rustflow against the expected results,
and the captures themselves against Wireshark.

`tests/test_conformance.py` runs these under pytest. Without pytest:

    python3 tests/conformance/check.py [--bin target/release/rustflow]
"""

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent.parent
CASES_DIR = TESTS_DIR / "fixtures" / "conformance"

# directory -> the `collect --input` protocol that reads it
INPUT = {
    "netflow_v5": "netflow",
    "netflow_v9": "netflow",
    "ipfix": "netflow",
    "sflow_v5": "sflow",
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


def fixtures() -> list[Fixture]:
    return [
        Fixture(path.parent.name, path.stem, path.with_suffix(".pcap"), document)
        for path in sorted(CASES_DIR.glob("*/*.json"))
        for document in [json.loads(path.read_text())]
    ]


def collected(rustflow_bin: Path, fixture: Fixture) -> list[dict]:
    """The packets rustflow reads from the capture, as `--format raw` prints
    them."""
    url = f"{INPUT[fixture.protocol]}+pcap://{fixture.pcap}"
    result = subprocess.run(
        [rustflow_bin, "collect", "--input", url, "--format", "raw"],
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


def tshark_installed() -> bool:
    return shutil.which("tshark") is not None


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


def tshark_differences(fixture: Fixture) -> list[str]:
    out = []
    expected = fixture.document.get("tshark", {})
    if expected:
        actual = tshark_fields(fixture.pcap, list(expected))
        out += differences(expected, actual, "tshark")
    if fixture.document.get("clean", True) and (found := tshark_problems(fixture.pcap)):
        out.append(f"tshark finds malformed frames:\n{found}")
    return out


def check_captures() -> int:
    if not tshark_installed():
        print("tshark is not installed")
        return 2
    failed = 0
    for fixture in fixtures():
        problems = tshark_differences(fixture)
        failed += bool(problems)
        print(f"{'BAD CAPTURE' if problems else 'ok':11} {fixture.id}")
        for line in problems:
            print(f"    {line}")
    print(f"{failed} bad captures")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bin", type=Path, help="the rustflow binary")
    parser.add_argument(
        "--captures",
        action="store_true",
        help="only cross-check the captures with tshark, without rustflow",
    )
    args = parser.parse_args()
    if args.captures:
        return check_captures()
    candidates = [args.bin] if args.bin else []
    candidates += [
        TESTS_DIR.parent / "target" / profile / "rustflow"
        for profile in ("release", "debug")
    ]
    rustflow_bin = next((c for c in candidates if c.is_file()), None)
    if rustflow_bin is None:
        print("no rustflow binary; run `cargo build --release` or pass --bin")
        return 2
    with_tshark = tshark_installed()
    if not with_tshark:
        print("tshark is not installed; the captures are not cross-checked")

    failed = deviations = 0
    for fixture in fixtures():
        problems = differences(fixture.document["expected"], collected(rustflow_bin, fixture))
        deviation = fixture.document.get("deviation")
        capture = tshark_differences(fixture) if with_tshark else []
        if deviation and problems:
            status, deviations = "DEVIATION", deviations + 1
        elif deviation:
            status, failed = "FIXED (drop the deviation note)", failed + 1
        elif problems:
            status, failed = "FAIL", failed + 1
        else:
            status = "ok"
        if capture:
            status, failed = f"{status} + BAD CAPTURE", failed + 1
        print(f"{status:10} {fixture.id}")
        if deviation and problems:
            print(f"    known: {deviation}")
        for line in (problems if status != "ok" else []) + capture:
            print(f"    {line}")
    print(f"{failed} failed, {deviations} known deviations")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
