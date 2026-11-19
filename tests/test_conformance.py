"""Protocol conformance: replay each capture under `fixtures/conformance/`
and compare what rustflow reads with the expected result beside it.

The expected results are written from the specifications, not recorded
from rustflow; see `conformance/README.md`. Each capture is also read by
Wireshark, where it is installed, to check the capture itself.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "conformance"))

import check  # noqa: E402

FIXTURES = check.fixtures()


def params():
    for fixture in FIXTURES:
        deviation = fixture.document.get("deviation")
        marks = [pytest.mark.xfail(reason=deviation, strict=True)] if deviation else []
        yield pytest.param(fixture, id=fixture.id, marks=marks)


@pytest.mark.parametrize("fixture", params())
def test_rustflow_reads_what_the_specification_says(rustflow_bin, fixture):
    actual = check.collected(rustflow_bin, fixture)
    problems = check.differences(fixture.document["expected"], actual)
    assert not problems, "\n".join(problems)


@pytest.mark.skipif(not check.tshark_installed(), reason="tshark is not installed")
@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.id for f in FIXTURES])
def test_wireshark_reads_the_capture_the_same_way(fixture):
    problems = check.tshark_differences(fixture)
    assert not problems, "\n".join(problems)
