"""Two registered public launch cases; no HE, native or crypto fixture exists."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from benchmarks import complete_cost_owner_launch as launch


def inputs():
    return Path(os.environ["Q77_DETACHED_PUBLIC_FIXTURE_ROOT"]).resolve(strict=True)


def wait_for(path):
    deadline = time.monotonic() + 8
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Bounded public probe did not return")
        time.sleep(0.02)


def test_detached_public_probe_survives_launcher_exit_and_consumes_its_slot():
    root = inputs()
    # The public parent actually exits while its child waits for a public file.
    result = subprocess.run(
        [sys.executable, str(root / "public-parent.py"), str(root), str(launch.ROOT)],
        cwd=launch.ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=8,
    )
    assert json.loads(result.stdout)["public_parent_returned"] is True
    output, directory = root / "probe-output", root / "probe-launch"
    record = json.loads((directory / "launch-record.json").read_text())
    wait_for(output / "ready.json")
    ready = json.loads((output / "ready.json").read_text())
    original = record["identity_at_launch"]
    assert original["pid"] == ready["pid"] == original["process_group"] == original["session"]
    assert launch.inspect(directory)["state"] == "original-process-live"
    spec = launch.DetachedSpec(
        sys.executable,
        launch.pinned(sys.executable),
        launch.pinned(root / "public-probe.py"),
        (str(output), str(root / "stop-probe")),
        str(launch.ROOT),
        str(output),
        str(directory),
    )
    try:
        with pytest.raises(ValueError, match="unconsumed"):
            launch.start_detached(spec, preflight=lambda: None)
    finally:
        # The owned public probe exits normally; no signal or reused PID is used.
        (root / "stop-probe").write_bytes(b"finish-public-probe")
    wait_for(output / "cohort-result.json")
    assert json.loads((output / "cohort-result.json").read_text()) == {
        "public_probe": True,
        "private_or_HE_work": False,
        "status": "complete",
    }
    assert launch.inspect(directory)["state"] == "terminal-return-present"
    assert (directory / "owner.stdout.log").read_text().strip() == "public-probe-complete"
    assert (directory / "owner.stderr.log").read_bytes() == b""


def test_changed_public_source_pin_cannot_create_a_child_or_consume_a_new_slot(monkeypatch):
    root = inputs()
    source = launch.pinned(root / "public-probe.py")
    spec = launch.DetachedSpec(
        sys.executable,
        launch.pinned(sys.executable),
        source,
        (str(root / "bad-output"), str(root / "stop-bad-probe")),
        str(launch.ROOT),
        str(root / "bad-output"),
        str(root / "bad-launch"),
    )
    calls = []
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *a, **k: calls.append((a, k)))
    bad = replace(spec, entry={**source, "sha256": "00" * 32})
    with pytest.raises(ValueError, match="pins"):
        launch.start_detached(bad, preflight=lambda: calls.append("preflight"))
    assert calls == []
    assert not Path(spec.cohort_output).exists()
    assert not Path(spec.launch_directory).exists()
