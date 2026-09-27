"""Pinned public UCI fixtures for research, with no network access on import.

Semeion uses its original 256 binary pixels. Mushroom uses the published
22-attribute categorical schema (126 indicator bits), including '?' as a
category; class labels are discarded. This benchmark is not a classifier.
Both UCI landing pages label the datasets CC BY 4.0; see the research report
for attribution and the distinction between handwritten and hypothetical data.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import random
from typing import TypedDict


class Source(TypedDict):
    url: str
    member: str
    count: int
    dimension: int
    archive_sha256: str
    file_sha256: str
    citation: str


SOURCES: dict[str, Source] = {
    "semeion": {
        "url": "https://archive.ics.uci.edu/static/public/178/semeion%2Bhandwritten%2Bdigit.zip",
        "member": "semeion.data", "count": 1593, "dimension": 256,
        "archive_sha256": "6fb091394714cddda5751d4e1c2781ab094e7cf15de07917fb40e581f19efc75",
        "file_sha256": "f43228ae3da5ea6a3c95069d53450b86166770e3b719dcc333182128fe08d4b1",
        "citation": "Semeion Handwritten Digit [Dataset] (1998), https://doi.org/10.24432/C5SC8V",
    },
    "mushroom": {
        "url": "https://archive.ics.uci.edu/static/public/73/mushroom.zip",
        "member": "agaricus-lepiota.data", "count": 8124, "dimension": 126,
        "archive_sha256": "face32f32647e0d939f6233f36dd30dd5d619ae9f3f9b8e10bea4ac7e1f60b1a",
        "file_sha256": "e65d082030501a3ebcbcd7c9f7c71aa9d28fdfff463bf4cf4716a3fe13ac360e",
        "citation": "Mushroom [Dataset] (1981), https://doi.org/10.24432/C5959T",
    },
}

# Fixed from the published schema, never inferred from held-out queries.
MUSHROOM_CATEGORIES = (
    "bcxfks", "fgys", "nbcgrpuewy", "tf", "alcyfmnps", "adfn", "cwd", "bn", "knbhgropuewy", "et",
    "bcuezr?", "fyks", "fyks", "nbcgopewy", "nbcgopewy", "pu", "nowy", "not", "ceflnpsz", "knbhrouwy",
    "acnsvy", "glmpuwd",
)


@dataclass(frozen=True)
class BinaryData:
    name: str
    dimension: int
    rows: tuple[int, ...]
    sha256: str


def parse_semeion(text: str) -> tuple[int, ...]:
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        tokens = line.split()
        if len(tokens) != 266:
            raise ValueError("Expected 256 pixels plus ten Semeion class indicators")
        values = [float(x) for x in tokens]
        if any(x not in (0.0, 1.0) for x in values) or sum(values[256:]) != 1:
            raise ValueError("Non-binary Semeion pixel or invalid label")
        result.append(sum(int(bit) << j for j, bit in enumerate(values[:256])))
    return tuple(result)


def parse_mushroom(text: str) -> tuple[int, ...]:
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        tokens = line.split(",")
        if len(tokens) != 23 or tokens[0] not in ("e", "p"):
            raise ValueError("Expected a Mushroom class plus 22 categories")
        offset = encoded = 0
        for value, alphabet in zip(tokens[1:], MUSHROOM_CATEGORIES, strict=True):
            if len(value) != 1 or value not in alphabet:
                raise ValueError("Mushroom value outside the published schema")
            encoded |= 1 << (offset + alphabet.index(value))
            offset += len(alphabet)
        result.append(encoded)
    return tuple(result)


def load(name: str, path: Path) -> BinaryData:
    if name not in SOURCES:
        raise ValueError("Unknown pinned binary fixture")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    source = SOURCES[name]
    if digest != source["file_sha256"]:
        raise ValueError("Dataset hash differs from the reviewed fixture")
    rows = (parse_semeion if name == "semeion" else parse_mushroom)(data.decode("ascii"))
    if len(rows) != source["count"]:
        raise ValueError("Unexpected fixture row count")
    return BinaryData(name, source["dimension"], rows, digest)


def split(data: BinaryData, seed: int, holdout: int = 128) -> tuple[list[int], list[int]]:
    """Return original source IDs; queries never enter index preprocessing."""
    if type(holdout) is not int or not 1 <= holdout < len(data.rows):
        raise ValueError("Require a nonempty query and index split")
    indices = list(range(len(data.rows)))
    random.Random(seed).shuffle(indices)
    return indices[holdout:], indices[:holdout]
