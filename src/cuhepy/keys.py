"""Save and restore a homomorphic keypair.

.. warning::

   :func:`save` writes the **secret key in plaintext**. The file is created with
   mode ``0600``, but protecting it beyond that -- disk encryption, a KMS, a
   passphrase wrapper -- is the caller's responsibility. ``cuhepy`` deliberately
   ships no key-management layer: it is a homomorphic-encryption library, not a
   secrets manager.

Usage::

    from cuhepy.paillier.lookup_client import PaillierLookupClient
    from cuhepy import keys

    client = PaillierLookupClient(embed_len=512, key_len=1024)
    keys.save(client, "key.json")
    restored = keys.load("key.json")
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cuhepy.device import DeviceMode

# Config keys accepted by each client's constructor. BFV round-trips its whole
# config except ``device``; the Paillier clients take a fixed subset.
_CTOR_KEYS: dict[str, tuple[str, ...] | None] = {
    "PaillierClient": ("embed_len", "key_len"),
    "PaillierLookupClient": ("embed_len", "key_len", "alpha_len"),
    "BFVClient": None,  # None means "every config key except device"
}


def _client_class(type_name: str) -> type[Any]:
    if type_name == "PaillierClient":
        from cuhepy.paillier.client import PaillierClient

        return PaillierClient
    if type_name == "PaillierLookupClient":
        from cuhepy.paillier.lookup_client import PaillierLookupClient

        return PaillierLookupClient
    if type_name == "BFVClient":
        from cuhepy.bfv.client import BFVClient

        return BFVClient
    raise ValueError(
        f"Unknown client type {type_name!r}; expected one of {sorted(_CTOR_KEYS)}"
    )


def save(client: Any, path: str | Path, *, include_tables: bool = False) -> None:
    """Write ``client``'s keypair and configuration to ``path`` as JSON.

    :param client: A ``PaillierClient``, ``PaillierLookupClient`` or ``BFVClient``.
    :param path: Destination file. Created with mode ``0600``.
    :param include_tables: Also store the Paillier-Lookup precomputed tables, so
        :func:`load` skips recomputing them. Large (tens of MB) but much faster
        to reload.
    """
    type_name = type(client).__name__
    if type_name not in _CTOR_KEYS:
        raise ValueError(f"Cannot save a {type_name}; expected one of {sorted(_CTOR_KEYS)}")

    blob: dict[str, Any] = {
        "type": type_name,
        "pk": client.stringify_pk(),
        "sk": client.stringify_sk(),
        "config": json.loads(client.stringify_config()),
    }
    if include_tables:
        dump = getattr(client, "dump_tables", None)
        if dump is not None:
            tables = dump()
            if tables:
                blob["tables"] = tables

    path = Path(path)
    # Create private, then write -- never widen an existing file's mode.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(blob, handle)


def load(path: str | Path, *, device: DeviceMode = "auto") -> Any:
    """Restore a client previously written by :func:`save`.

    :param path: File to read.
    :param device: Backend for the restored client. Keys are portable, so a
        keypair generated on CPU loads on GPU and vice versa.
    """
    blob = json.loads(Path(path).read_text())
    cls = _client_class(blob["type"])
    config = blob["config"]

    accepted = _CTOR_KEYS[blob["type"]]
    if accepted is None:
        kwargs = {k: v for k, v in config.items() if k != "device"}
    else:
        kwargs = {k: config[k] for k in accepted if k in config}

    client = cls(**kwargs, skip_key_gen=True, device=device)
    client.load_stringified_keys(blob["pk"], blob["sk"])

    tables = blob.get("tables")
    if tables is not None and blob["type"] == "PaillierLookupClient":
        client.load_config(config, precomputed_tables=tables)
    else:
        client.load_config(config)
    return client
