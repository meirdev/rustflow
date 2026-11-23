"""Writes the conformance captures and their expected results.

    python3 tests/conformance/generate.py

Each case becomes `fixtures/conformance/<protocol>/<name>.pcap` and
`<name>.json` beside it; `INDEX.md` lists them by the section they cover.
The output is deterministic: running this again changes nothing unless a
case changed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ipfix  # noqa: E402
import netflow_v5  # noqa: E402
import netflow_v9  # noqa: E402
import sflow_v5  # noqa: E402
import vendors  # noqa: E402
from wire import Case, write_pcap  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "conformance"

PROTOCOLS = {
    "netflow_v5": ("NetFlow v5", netflow_v5),
    "netflow_v9": ("NetFlow v9", netflow_v9),
    "ipfix": ("IPFIX", ipfix),
    "sflow_v5": ("sFlow v5", sflow_v5),
    "vendors": ("Vendors and models", vendors),
}


def dump(value, indent: int = 0) -> str:
    """JSON with one line for each object or array that holds only scalars."""
    pad = "  " * indent
    nested = value.values() if isinstance(value, dict) else value
    if not isinstance(value, (dict, list)) or not any(
        isinstance(item, (dict, list)) for item in nested
    ):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, dict):
        items = (
            f"{pad}  {json.dumps(key)}: {dump(item, indent + 1)}"
            for key, item in value.items()
        )
        return "{\n" + ",\n".join(items) + f"\n{pad}}}"
    items = (f"{pad}  {dump(item, indent + 1)}" for item in value)
    return "[\n" + ",\n".join(items) + f"\n{pad}]"


def write_case(directory: Path, case: Case) -> None:
    write_pcap(directory / f"{case.name}.pcap", case.datagrams)
    document = {
        "reference": case.reference,
        "description": case.description,
        "datagrams": len(case.datagrams),
        "expected": case.expected,
        "flows": case.flows,
    }
    if case.tshark:
        document["tshark"] = case.tshark
    if not case.clean:
        document["clean"] = False
    if case.deviation:
        document["deviation"] = case.deviation
    (directory / f"{case.name}.json").write_text(dump(document) + "\n")


def main() -> None:
    index = [
        "# Conformance cases",
        "",
        "Written by `tests/conformance/generate.py`; do not edit.",
    ]
    total = 0
    for directory_name, (title, module) in PROTOCOLS.items():
        directory = OUT_DIR / directory_name
        directory.mkdir(parents=True, exist_ok=True)
        cases = module.cases()
        names = [case.name for case in cases]
        assert len(names) == len(set(names)), f"duplicate case name in {title}"
        for stale in directory.iterdir():
            if stale.stem not in names:
                stale.unlink()
        index += ["", f"## {title}", "", "| Case | Covers | What it checks |"]
        index += ["| --- | --- | --- |"]
        for case in cases:
            write_case(directory, case)
            note = f" **Known deviation:** {case.deviation}" if case.deviation else ""
            index.append(
                f"| `{case.name}` | {case.reference} | {case.description}{note} |"
            )
        total += len(cases)
    (OUT_DIR / "INDEX.md").write_text("\n".join(index) + "\n")
    print(f"{total} cases written to {OUT_DIR}")


if __name__ == "__main__":
    main()
