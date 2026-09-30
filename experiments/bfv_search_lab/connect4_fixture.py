"""Independent larger real categorical fixture; old fixture catalog unchanged.

John Tromp (1995), Connect-4, UCI, doi:10.24432/C59P43, CC BY 4.0.
Each of 42 published board cells becomes three indicator bits (b,x,o), so
binary Hamming distance is exactly twice board-cell mismatch. Outcome labels
are discarded. This is game-position Hamming, not text retrieval or evidence
of customer update frequencies. Source/decompression hashes are pinned.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from experiments.bfv_search_lab.binary_fixtures import BinaryData

SOURCE = {
    "url": "https://archive.ics.uci.edu/static/public/26/connect%2B4.zip",
    "landing": "https://archive.ics.uci.edu/dataset/26/connect%2B4",
    "citation": "Tromp, J. (1995). Connect-4 [Dataset]. https://doi.org/10.24432/C59P43",
    "license": "CC BY 4.0",
    "archive_sha256": "81cc51ce1556f1f927bf0d6f3f16f61e277bb8647c5a49426d272b792a30a205",
    "Z_sha256": "14c886b817783ac9b642f42ec78a2e67f727a3d41c94913af8954d454eee2367",
    "file_sha256": "063152e6eadbb424c7ef4645df76e493a43812edd9c992400983da4fa54f8cba",
    "count": 67557, "dimension": 126,
}


def parse(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        values = line.split(",")
        if len(values) != 43 or values[-1] not in ("win", "loss", "draw"):
            raise ValueError("Expected 42 Connect-4 cells and an outcome")
        if any(value not in ("b", "x", "o") for value in values[:-1]):
            raise ValueError("Connect-4 cell outside published category schema")
        rows.append(sum(1 << (3 * j + "bxo".index(value)) for j, value in enumerate(values[:-1])))
    return tuple(rows)


def load(path: Path):
    body = path.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    if digest != SOURCE["file_sha256"]:
        raise ValueError("Connect-4 fixture differs from pinned source")
    rows = parse(body.decode("ascii"))
    if len(rows) != SOURCE["count"]:
        raise ValueError("Unexpected Connect-4 row count")
    return BinaryData("connect4", SOURCE["dimension"], rows, digest)
