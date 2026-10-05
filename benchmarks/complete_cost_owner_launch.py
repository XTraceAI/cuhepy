"""Launch one frozen complete-cost study independently of its observer lifetime.

The actual OwnerStudy still owns every crypto budget, worker, guard and deadline.
This launcher has no HE key, worker replacement, retry or resume path. The CLI
only invokes the pinned existing study; helper injection is for trusted public
tests, never a network-selected entry point. Launch receipts and stdout/stderr
are outside the cohort root, whose name remains consumed if the owner starts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def pinned(path):
    path = Path(path).resolve(strict=True)
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            size += len(block)
            digest.update(block)
    return {"file": str(path), "bytes": size, "sha256": digest.hexdigest()}


def write_once(path, value):
    with Path(path).open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    except FileNotFoundError:
        return None
    return {
        "pid": pid,
        "birth_ticks": int(fields[19]),
        "state": fields[0],
        "parent": int(fields[1]),
        "process_group": int(fields[2]),
        "session": int(fields[3]),
    }


@dataclass(frozen=True)
class DetachedSpec:
    python_invocation: str
    python_pin: dict
    entry: dict
    arguments: tuple[str, ...]
    cwd: str
    cohort_output: str
    launch_directory: str

    def validate(self):
        if (
            type(self.python_invocation) is not str
            or not Path(self.python_invocation).is_absolute()
            or pinned(self.python_invocation) != self.python_pin
            or pinned(self.entry["file"]) != self.entry
            or type(self.arguments) is not tuple
            or len(self.arguments) > 16
            or any(type(x) is not str or not x or "\0" in x for x in self.arguments)
        ):
            raise ValueError("Exact trusted Python/source/argument pins required")
        cwd = Path(self.cwd).resolve(strict=True)
        if not cwd.is_dir():
            raise ValueError("Existing trusted cwd required")
        for value in (self.cohort_output, self.launch_directory):
            path = Path(value)
            if not path.is_absolute() or path.exists() or path.is_symlink():
                raise ValueError("Absolute unconsumed cohort and launch paths required")
            if path.parent.resolve(strict=True) != path.parent:
                raise ValueError("Existing canonical parent path required")
        if self.cohort_output == self.launch_directory:
            raise ValueError("Observer directory must be outside the actual cohort root")


def start_detached(spec, *, preflight):
    """Exclusive reservation precedes Popen; no implicit retry on any failure.

    The trusted CLI supplies the actual committed-study preflight. A public
    fixture can supply a labelled no-HE preflight and pinned public probe.
    No helper accepts a caller-provided shell command or interpreter flags.
    """
    if type(spec) is not DetachedSpec or not callable(preflight):
        raise ValueError("Trusted fixed detached launch specification required")
    spec.validate()
    preflight()
    directory = Path(spec.launch_directory)
    directory.mkdir()  # The slot stays consumed even if Popen fails.
    command = [spec.python_invocation, spec.entry["file"], *spec.arguments]
    write_once(
        directory / "launch-attempt.json",
        {
            "utc": datetime.now(timezone.utc).isoformat(),
            "started_ns": time.perf_counter_ns(),
            "launcher": pinned(__file__),
            "python_pin": spec.python_pin,
            "entry": spec.entry,
            "command": command,
            "cwd": spec.cwd,
            "cohort_output": spec.cohort_output,
            "automatic_retry_or_resume": False,
            "private_keys_created_or_serialized": False,
        },
    )
    try:
        with (directory / "owner.stdout.log").open("xb") as stdout:
            with (directory / "owner.stderr.log").open("xb") as stderr:
                process = subprocess.Popen(
                    command,
                    cwd=spec.cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                    close_fds=True,
                )
        identity = process_identity(process.pid)
        record = {
            "utc": datetime.now(timezone.utc).isoformat(),
            "pid": process.pid,
            "identity_at_launch": identity,
            "cohort_output": spec.cohort_output,
            "launch_directory": spec.launch_directory,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "returncode_if_already_exited": process.poll(),
            "execution_is_not_bound_to_observer_stdin_stdout_or_session": True,
            "actual_terminal_result_not_asserted": True,
        }
        write_once(directory / "launch-record.json", record)
        return record
    except BaseException as error:
        write_once(
            directory / "launch-failure.json",
            {
                "error_class": type(error).__name__,
                "slot_stays_consumed": True,
                "process_may_have_started_do_not_retry": True,
            },
        )
        raise


def inspect(directory):
    """Read a recorded original identity; never use a stale PID to stop a peer."""
    directory = Path(directory).resolve(strict=True)
    record = json.loads((directory / "launch-record.json").read_text())
    terminal = Path(record["cohort_output"]) / "cohort-result.json"
    current = process_identity(record["pid"])
    original = record["identity_at_launch"]
    same_boot = record["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    matched = bool(
        same_boot and original and current and original["birth_ticks"] == current["birth_ticks"]
    )
    state = (
        "terminal-return-present"
        if terminal.exists()
        else (
            "original-process-live"
            if matched and current["state"] != "Z"
            else "original-process-absent-without-terminal-return"
        )
    )
    return {
        "utc": datetime.now(timezone.utc).isoformat(),
        "state": state,
        "same_boot": same_boot,
        "original_pid_birth_matched": matched,
        "observed_original_identity": current if matched else None,
        "actual_terminal_return": pinned(terminal) if terminal.exists() else None,
        "restart_resume_process_signal_or_private_work": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("launch", "inspect"))
    parser.add_argument("--launch-directory", type=Path, required=True)
    parser.add_argument("--addendum", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "inspect":
        print(json.dumps(inspect(args.launch_directory), indent=2))
        return
    if args.addendum is None or args.output is None:
        parser.error("launch requires --addendum and a fresh --output")
    # Existing code performs its full pure committed preflight before any key.
    # Import is deliberately deferred; the public helper has only stdlib imports.
    sys.path.insert(0, str(ROOT))
    from benchmarks import complete_cost_owner_study as study

    freeze = study.validate_execution(args.addendum)
    entry = pinned(study.__file__)
    if entry not in freeze["new_sources"] + freeze["preserved_runtime_sources"]:
        raise ValueError("Actual complete study source is not frozen")
    if pinned(__file__) not in freeze["new_sources"] + freeze["preserved_runtime_sources"]:
        raise ValueError("Actual detached launcher source is not frozen")
    spec = DetachedSpec(
        str(ROOT / ".venv/bin/python"),
        freeze["python"],
        entry,
        (
            "run",
            "--addendum",
            str(args.addendum.resolve(strict=True)),
            "--output",
            str(args.output.resolve()),
        ),
        str(ROOT),
        str(args.output.resolve()),
        str(args.launch_directory.resolve()),
    )
    record = start_detached(spec, preflight=lambda: study.validate_execution(args.addendum))
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
