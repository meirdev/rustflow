"""`--expire`: old files of the collector's own are removed from the output
tree, everything else is left alone, and the option is validated."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

STAMP = "%Y%m%dT%H%M%SZ"


def touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


def test_old_files_are_removed_and_the_rest_kept(collect, pcap_dir, tmp_path):
    out = tmp_path / "out"
    heard = tmp_path / "heard"
    heard.mkdir()
    recent = (datetime.now(UTC) - timedelta(minutes=30)).strftime(STAMP)
    old = [
        touch(out / "flows-20260101T000000Z.parquet"),
        touch(out / "2026/01/05/10/flows-20260105T100000Z.parquet"),
        touch(out / "2026/01/05/10/flows-20260105T100000Z-1.parquet"),
        touch(out / "2026/01/05/10/.flows-20260105T100500Z.parquet.12.tmp"),
    ]
    kept = [
        touch(out / f"flows-{recent}.parquet"),
        touch(out / "2026/01/05/11/other-20260105T110000Z.parquet"),
        touch(out / "2026/01/05/11/flows-20260105T110000Z.csv"),
        touch(out / "notes.txt"),
    ]

    collect(
        pcap_dir / "ipfix_sanity.pcap",
        "netflow",
        "--format", "common", "--serialization", "parquet",
        "--output", str(out), "--interval", "1m", "--level", "2", "--expire", "1h",
        "--expire-exec", f"touch {heard}/%t",
    )

    for path in old:
        assert not path.exists(), path
    for path in kept:
        assert path.exists(), path
    assert not (out / "2026/01/05/10").exists()
    assert (out / "2026/01/05/11").exists()
    written = [p for p in out.rglob("flows-*.parquet") if p not in kept]
    assert len(written) == 1, written
    # The hook heard of the complete files, not of the temporary one.
    assert sorted(p.name for p in heard.iterdir()) == [
        "20260101T000000Z",
        "20260105T100000Z",
    ]


@pytest.mark.parametrize(
    "args,message",
    [
        (["--interval", "1m", "--expire", "30s"], "at least as long as --interval"),
        (["--expire", "1h"], "required arguments were not provided"),
    ],
    ids=["shorter-than-interval", "without-interval"],
)
def test_expire_is_validated(collect, pcap_dir, tmp_path, args, message):
    with pytest.raises(subprocess.CalledProcessError) as error:
        collect(
            pcap_dir / "ipfix_sanity.pcap",
            "netflow",
            "--format", "common", "--serialization", "parquet",
            "--output", str(tmp_path / "out"), *args,
        )
    assert message in error.value.stderr.decode()
