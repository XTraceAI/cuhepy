#!/usr/bin/env python3
"""Plan or explicitly restore pinned user-level CUDA correctness tools.

The default is a data-only plan. Run --execute after the serial timing queue;
it downloads four official redistributables into an entirely new directory.
No driver, global package, native extension or Valgrind build is installed.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import signal
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
REDIST = "https://developer.download.nvidia.com/compute/cuda/redist/"
AUDIT_SHA256 = "785559dc79ab4d95b06958d26339696b0514a3ec17f0d24cd0ae40abbcbe2951"
PINS = {
    "cuda_nvcc": ("12.9.86", "7a1a5b652e5ef85c82b721d10672fc9a2dbaab44e9bd3c65a69517bf53998c35", 81100244),
    "cuda_cudart": ("12.9.79", "1f6ad42d4f530b24bfa35894ccf6b7209d2354f59101fd62ec4a6192a184ce99", 1514676),
    "cuda_cccl": ("12.9.27", "8b1a5095669e94f2f9afd7715533314d418179e9452be61e2fde4c82a3e542aa", 997888),
    "cuda_sanitizer_api": ("12.9.79", "e23aad21132ff58b92a22aad372a7048793400b79c625665d325d4ecec6979bf", 9758036),
}


def utc():
    return datetime.now(UTC).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stop_owned(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


@contextmanager
def stage_budget(seconds):
    """Bound in-process hashing/extraction/merge, not somebody else's worker."""
    previous = signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError("Recovery requires its own unused process timer")

    def expired(signum, frame):
        raise TimeoutError("Recovery stage time budget exceeded")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def invoke(command, output, label, timeout):
    stdout, stderr = output / (label + ".stdout.log"), output / (label + ".stderr.log")
    row = {"command": [str(x) for x in command], "start_utc": utc(), "timeout_s": timeout}
    start, process = time.monotonic(), None
    with stdout.open("x") as out, stderr.open("x") as err:
        try:
            process = subprocess.Popen(row["command"], stdout=out, stderr=err, start_new_session=True)
            try:
                row["returncode"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_owned(process)
                row.update(returncode=124, timeout=True)
        except OSError as error:
            row.update(returncode=127, launch_error=str(error))
        except BaseException:
            if process is not None and process.poll() is None:
                stop_owned(process)
            raise
    row.update(end_utc=utc(), diagnostic_wall_s=time.monotonic() - start,
               stdout=str(stdout), stderr=str(stderr), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    return row


def validated_members(archive):
    members, names, roots, total = [], set(), set(), 0
    for member in archive.getmembers():
        parts = PurePosixPath(member.name).parts
        if not parts or member.name.startswith("/") or ".." in parts:
            raise ValueError("Unsafe archive member: " + member.name)
        normalized = posixpath.normpath(member.name)
        if normalized in names:
            raise ValueError("Duplicate archive member: " + normalized)
        names.add(normalized)
        roots.add(parts[0])
        if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
            raise ValueError("Special archive file rejected: " + member.name)
        if member.issym() or member.islnk():
            link = member.linkname
            if not link or link.startswith("/"):
                raise ValueError("Absolute/empty archive link: " + member.name)
            joined = posixpath.join(posixpath.dirname(normalized), link) if member.issym() else link
            target = PurePosixPath(posixpath.normpath(joined))
            if not target.parts or target.parts[0] != parts[0] or ".." in target.parts:
                raise ValueError("Archive link escapes component: " + member.name)
        total += member.size if member.isfile() else 0
        if total > 2 * 1024 ** 3 or len(members) >= 100000:
            raise ValueError("Archive exceeds bounded member/expanded-size policy")
        members.append(member)
    if len(roots) != 1:
        raise ValueError("Archive requires exactly one preserved component root")
    return members, roots.pop(), total


def tree_identity(root):
    entries = []
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(parent) / name
            item = {"path": str(path.relative_to(root)), "mode": path.lstat().st_mode & 0o777}
            if path.is_symlink():
                if not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError("Installed symlink escapes root: " + str(path))
                item.update(kind="symlink", target=os.readlink(path), target_exists=path.exists())
            elif path.is_file():
                item.update(kind="file", bytes=path.stat().st_size, sha256=sha(path))
            elif path.is_dir():
                item.update(kind="directory")
            else:
                raise ValueError("Unexpected installed file type: " + str(path))
            entries.append(item)
    entries.sort(key=lambda x: x["path"])
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(canonical).hexdigest(), "entries": entries,
            "regular_file_bytes": sum(x.get("bytes", 0) for x in entries)}


def merge_component(component, destination, skipped, name):
    """Copy component layout without traversing symlinks or replacing files."""
    def copy(source, target):
        occupied = target.exists() or target.is_symlink()
        if source.is_symlink():
            value = os.readlink(source)
            if occupied:
                if not target.is_symlink() or os.readlink(target) != value:
                    raise ValueError("Conflicting CUDA link: " + str(target))
            else:
                target.symlink_to(value)
        elif source.is_dir():
            if occupied and (target.is_symlink() or not target.is_dir()):
                raise ValueError("Conflicting CUDA directory: " + str(target))
            target.mkdir(exist_ok=True)
            for child in sorted(source.iterdir()):
                copy(child, target / child.name)
        elif source.is_file():
            if occupied:
                if not target.is_symlink() and target.is_file() and sha(source) == sha(target):
                    return
                if source.parent == component and source.name.lower().startswith(("license", "eula")):
                    skipped.append({"component": name, "metadata_file": source.name,
                                    "reason": "Different component license retained in component root; merged root already has one."})
                    return
                raise ValueError("Conflicting CUDA file: " + str(target))
            shutil.copy2(source, target, follow_symlinks=False)
        else:
            raise ValueError("Unexpected CUDA component file: " + str(source))
    for child in sorted(component.iterdir()):
        copy(child, destination / child.name)


def installed_tool(root, name):
    """Select the pinned component layout, including NVIDIA's shell launcher."""
    expected = {
        "nvcc": ("bin/nvcc",),
        "compute-sanitizer": ("compute-sanitizer/compute-sanitizer", "bin/compute-sanitizer"),
    }[name]
    candidates = sorted(p for p in root.rglob(name) if p.is_file() and os.access(p, os.X_OK))
    allowed = {root / relative for relative in expected}
    primary = root / expected[0]
    if primary not in candidates or set(candidates) - allowed:
        raise ValueError("Unexpected installed executable layout for " + name + ": " + str(candidates))
    if any(not p.resolve().is_relative_to(root.resolve()) for p in candidates):
        raise ValueError("Installed tool escapes verified CUDA root")
    return primary.resolve(), [{"path": str(p), "sha256": sha(p)} for p in candidates]


def make_plan(args):
    audit_body = args.audit.read_bytes()
    digest = hashlib.sha256(audit_body).hexdigest()
    if digest != AUDIT_SHA256:
        raise ValueError("Recovery audit changed; review/re-pin helper rather than silently accept new recipe")
    audit = json.loads(audit_body)
    recipes = {x["component"]: x for x in audit["cuda_recommendation"]["archive_plan"]}
    output = args.output.resolve()
    allowed = (ROOT.parent / "research-data/revalidation-20261001").resolve()
    if output == allowed or not output.is_relative_to(allowed):
        raise ValueError("Recovery output must be a fresh task-owned revalidation subdirectory; no global install")
    archives = []
    for name, (version, expected, size) in PINS.items():
        filename = name + "-linux-x86_64-" + version + "-archive.tar.xz"
        url = REDIST + name + "/linux-x86_64/" + filename
        item = recipes[name]
        if (item["version"], item["url"], item["sha256"], item["bytes"]) != (version, url, expected, size):
            raise ValueError("Audit disagrees with official hardcoded component pin: " + name)
        archive = output / "downloads" / filename
        command = [str(args.curl), "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                   "--retry", "2", "--connect-timeout", "30", "--max-time", "600", "--retry-max-time", "1200",
                   "--max-filesize", str(size), "--output", str(archive) + ".part", url]
        archives.append({"component": name, "version": version, "url": url, "sha256": expected,
                         "bytes": size, "archive": str(archive), "download_command": command,
                         "status": "proposed_not_downloaded"})
    return {"schema": 1, "created_utc": utc(), "mode": "execute" if args.execute else "plan",
            "audit": str(args.audit.resolve()), "audit_sha256": digest, "runner_sha256": sha(Path(__file__)),
            "output": str(output), "cuda_root": str(output / "cuda-12.9.1"), "archives": archives,
            "total_download_bytes": sum(x["bytes"] for x in archives), "steps": [], "tools": {},
            "in_process_stage_timeout_s": args.stage_timeout_s,
            "valgrind": {"status": "separate_proposal_only_not_downloaded_built_or_installed",
                         **{k: v for k, v in audit["valgrind_recommendation"].items() if k not in ("commands", "taint_jobs")}},
            "scope": "User-level official CUDA redistributables only, after timed queue. Default plan makes no output directory, download, extraction, tool probe or install. Existing global/driver/tools and delivered extensions unchanged. Fresh extraction/merged roots publish atomically. Valgrind source build is a separate proposal requiring reviewed authentication and logs."}


def execute(plan, args):
    output = Path(plan["output"])
    if output.exists() or output.is_symlink():
        raise ValueError("Entirely fresh output required; never replace retained recovery attempts")
    curl = args.curl.resolve()
    if not curl.is_file() or not os.access(curl, os.X_OK):
        raise ValueError("Explicit curl executable unavailable")
    output.mkdir(parents=True)
    logs, downloads, components = output / "logs", output / "downloads", output / "components"
    for path in (logs, downloads, components):
        path.mkdir()
    receipt = output / "receipt.json"

    def save():
        receipt.write_text(json.dumps(plan, indent=2) + "\n")

    plan.update(start_utc=utc(), status="executing", curl_path=str(curl), curl_sha256=sha(curl))
    save()
    try:
        version = invoke([curl, "--version"], logs, "curl-version", 30)
        plan["steps"].append(version)
        if version["returncode"]:
            raise RuntimeError("curl version probe failed")
        for item in plan["archives"]:
            archive, component = Path(item["archive"]), components / item["component"]
            step = invoke(item["download_command"], logs, item["component"] + "-download", 1260)
            plan["steps"].append(step)
            save()
            if step["returncode"]:
                raise RuntimeError("Download failed: " + item["component"])
            part = archive.with_name(archive.name + ".part")
            with stage_budget(args.stage_timeout_s):
                item["downloaded_bytes"] = part.stat().st_size
                item["downloaded_sha256"] = sha(part)
                if item["downloaded_bytes"] != item["bytes"] or item["downloaded_sha256"] != item["sha256"]:
                    raise ValueError("Download size/SHA256 mismatch: " + item["component"])
                part.rename(archive)
                staging = components / ("." + item["component"] + ".part")
                staging.mkdir()
                with tarfile.open(archive, "r:xz") as bundle:
                    members, root_name, total = validated_members(bundle)
                    item.update(member_count=len(members), expanded_regular_bytes=total,
                                extraction_policy="prevalidated one-root paths/types/links, 2GiB/100000 member caps, Python data filter")
                    bundle.extractall(staging, members=members, filter="data")
                extracted = staging / root_name
                identity = tree_identity(extracted)
                extracted.rename(component)
                staging.rmdir()
            item.update(status="verified_and_extracted", component_root=str(component), tree_identity=identity)
            save()
        with stage_budget(args.stage_timeout_s):
            staged = output / ".cuda-12.9.1.part"
            staged.mkdir()
            plan["merged_metadata_collisions_preserved_in_components"] = []
            for item in plan["archives"]:
                merge_component(Path(item["component_root"]), staged,
                                plan["merged_metadata_collisions_preserved_in_components"], item["component"])
            if (staged / "lib").is_dir() and not (staged / "lib64").exists() and not (staged / "lib64").is_symlink():
                (staged / "lib64").symlink_to("lib", target_is_directory=True)
                plan["compatibility_links"] = [{"path": "lib64", "target": "lib"}]
            if not (staged / "bin/nvcc").is_file() or not (staged / "include/cuda_runtime.h").is_file():
                raise ValueError("Merged CUDA root lacks nvcc or runtime headers")
            if not list((staged / "nvvm/libdevice").glob("*.bc")):
                raise ValueError("Merged CUDA root lacks nvvm/libdevice bitcode")
            plan["merged_tree_identity"] = tree_identity(staged)
            staged.rename(Path(plan["cuda_root"]))
        root = Path(plan["cuda_root"])
        for name in ("nvcc", "compute-sanitizer"):
            path, candidates = installed_tool(root, name)
            step = invoke([path, "--version"], logs, name + "-version", 30)
            plan["steps"].append(step)
            plan["tools"][name] = {"path": str(path), "sha256": sha(path), "version_probe": step,
                                  "version_text": Path(step["stdout"]).read_text(),
                                  "installed_candidates": candidates}
            if step["returncode"]:
                raise RuntimeError("Installed tool version probe failed: " + name)
            save()
        plan.update(status="installed_and_version_probed", success=True)
    except BaseException as error:
        plan.update(status="failed_retained_attempt", success=False,
                    error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        plan["end_utc"] = utc()
        save()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=ROOT.parent / "research-data/revalidation-20261001/tool-recovery-audit.json")
    parser.add_argument("--output", type=Path, required=True, help="Entirely fresh user-level recovery directory")
    parser.add_argument("--curl", type=Path, default=Path("/usr/bin/curl"))
    parser.add_argument("--stage-timeout-s", type=int, default=600)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--plan", action="store_true", help="Default: print data only")
    group.add_argument("--execute", action="store_true", help="Download/extract/probe only after timed queue completes")
    args = parser.parse_args()
    if not 1 <= args.stage_timeout_s <= 1800:
        parser.error("Stage timeout must be1..1800 seconds")
    plan = make_plan(args)
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    receipt = execute(plan, args)
    print(json.dumps({"receipt": str(receipt), "receipt_sha256": sha(receipt),
                      "cuda_root": plan["cuda_root"], "tools": plan["tools"], "success": plan["success"]}))
    return 0 if plan["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
