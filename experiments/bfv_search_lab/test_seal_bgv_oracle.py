"""Optional external-library circuit check, with all coefficients verified."""

import json
import os
import random
import subprocess

import pytest

ORACLE = os.environ.get("CUHEPY_SEAL_BGV_ORACLE")


@pytest.mark.skipif(not ORACLE, reason="Build the optional SEAL 4.1.2 BGV oracle")
@pytest.mark.parametrize("dimension,count", [(1, 3), (3, 7), (31, 1025), (512, 65), (512, 16385)])
def test_external_bgv_circuits(dimension, count):
    rng = random.Random(dimension + count)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [query, [1 - x for x in query]]
    rows += [[rng.randrange(2) for _ in range(dimension)] for _ in range(count - 2)]
    fixture = f"16384 {dimension} {count}\n" + " ".join(map(str, query)) + "\n"
    fixture += "\n".join(" ".join(map(str, row)) for row in rows) + "\n"
    result = subprocess.run([ORACLE], input=fixture, text=True, capture_output=True, timeout=180, check=True)
    report = json.loads(result.stdout)
    assert report["seal_version"] == "4.1.2"
    assert report["both_circuits_correct"] is True
    assert report["coefficients_checked"] == 2 * 16384 * ((count + 16383) // 16384)
