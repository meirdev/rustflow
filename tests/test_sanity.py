"""Sanity checks: replay each fixture pcap in every output variant and
compare with the recorded snapshot under `fixtures/snapshots/`.

A snapshot is `<pcap>.<variant>.<ext>`; Parquet is stored as text (schema
plus one JSON row per line) so a failing diff is readable.
"""

import json
from datetime import datetime
from pathlib import Path

import pyarrow.parquet as pq
import pytest

# pcap name -> --flow-type
PCAPS = {
    "netflow_v5": "netflow",
    "netflow_v9": "netflow",
    "ipfix": "netflow",
    "sflow_v5": "sflow",
}

# (variant, --format, --serialization)
VARIANTS = [
    ("raw", "raw", "ndjson"),
    ("common", "common", "ndjson"),
    ("common", "common", "csv"),
    ("common", "common", "protobuf"),
    ("common", "common", "parquet"),
    ("enriched", "common", "ndjson"),
    ("enriched", "common", "csv"),
    ("enriched", "common", "protobuf"),
    ("enriched", "common", "parquet"),
]

EXTENSION = {
    "ndjson": "ndjson",
    "csv": "csv",
    "protobuf": "pb",
    "parquet": "parquet.txt",
}


def parquet_as_text(path: Path) -> bytes:
    table = pq.read_table(path)
    lines = [str(table.schema).replace("\n", "\n  "), ""]
    for row in table.to_pylist():
        lines.append(
            json.dumps(
                row,
                default=lambda v: v.isoformat() if isinstance(v, datetime) else str(v),
            )
        )
    return ("\n".join(lines) + "\n").encode()


@pytest.mark.parametrize(
    "variant,fmt,serialization", VARIANTS, ids=[f"{v[0]}-{v[2]}" for v in VARIANTS]
)
@pytest.mark.parametrize("name", PCAPS)
def test_snapshot(
    collect,
    enrich_args,
    pcap_dir,
    snapshot_dir,
    tmp_path,
    name,
    variant,
    fmt,
    serialization,
):
    pcap = pcap_dir / f"{name}_sanity.pcap"
    args = [
        "--flow-type",
        PCAPS[name],
        "--format",
        fmt,
        "--serialization",
        serialization,
    ]
    if variant == "enriched":
        args += enrich_args

    if serialization == "parquet":
        output = tmp_path / "out.parquet"
        collect(pcap, *args, output=output)
        actual = parquet_as_text(output)
    else:
        actual = collect(pcap, *args)

    expected = (
        snapshot_dir / f"{name}.{variant}.{EXTENSION[serialization]}"
    ).read_bytes()
    if serialization == "protobuf":
        assert actual == expected
    else:
        assert actual.decode() == expected.decode()
