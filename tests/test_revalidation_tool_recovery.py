"""The official sanitizer ships both an ELF executable and a shell launcher."""

import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "revalidation_tool_recovery",
    Path(__file__).resolve().parents[1] / "benchmarks/revalidation_tool_recovery.py",
)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(0o755)


def test_official_launcher_and_executable_have_distinct_identities(tmp_path):
    primary = tmp_path / "compute-sanitizer/compute-sanitizer"
    launcher = tmp_path / "bin/compute-sanitizer"
    executable(primary, b"canonical executable")
    executable(launcher, b"shell launcher")
    selected, identities = recovery.installed_tool(tmp_path, "compute-sanitizer")
    assert selected == primary
    assert {row["path"] for row in identities} == {str(primary), str(launcher)}
    assert len({row["sha256"] for row in identities}) == 2


@pytest.mark.parametrize("layout", ["unknown_executable", "missing_canonical", "escaping_link"])
def test_unreviewed_tool_layout_is_rejected(tmp_path, layout):
    root = tmp_path / "cuda"
    primary = root / "compute-sanitizer/compute-sanitizer"
    executable(root / "bin/compute-sanitizer", b"launcher")
    if layout == "unknown_executable":
        executable(primary, b"canonical")
        executable(root / "unreviewed/compute-sanitizer", b"different executable")
    elif layout == "escaping_link":
        outside = tmp_path / "foreign"
        executable(outside, b"foreign executable")
        primary.parent.mkdir(parents=True)
        primary.symlink_to(outside)
    with pytest.raises(ValueError):
        recovery.installed_tool(root, "compute-sanitizer")
