#!/usr/bin/env python3
"""Fetch the two small pinned CC BY 4.0 UCI fixtures; raw data stays outside Git."""

# ruff: noqa: E402 -- standalone research utility.

import argparse
import hashlib
import io
from pathlib import Path
import sys
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.bfv_search_lab.binary_fixtures import SOURCES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--datasets", nargs="+", choices=tuple(SOURCES), default=list(SOURCES))
    args = parser.parse_args()
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    for name in args.datasets:
        source = SOURCES[name]
        path = args.cache_dir / str(source["member"])
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != source["file_sha256"]:
                raise ValueError(f"Existing {path} differs from the pinned dataset")
            print(f"Verified cached {name}")
            continue
        with urllib.request.urlopen(str(source["url"]), timeout=30) as response:
            archive = response.read((8 << 20) + 1)
        if len(archive) > 8 << 20 or hashlib.sha256(archive).hexdigest() != source["archive_sha256"]:
            raise ValueError(f"Unexpected {name} archive")
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            member = z.getinfo(str(source["member"]))
            if member.file_size > 8 << 20:
                raise ValueError("Dataset exceeds the bounded fixture size")
            data = z.read(member)  # Whitelisted member; no archive path extraction.
        if hashlib.sha256(data).hexdigest() != source["file_sha256"]:
            raise ValueError("Unexpected dataset body")
        path.write_bytes(data)
        print(f"Downloaded {name}: {source['citation']} (CC BY 4.0)")


if __name__ == "__main__":
    main()
