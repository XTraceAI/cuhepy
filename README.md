<div align="center">

# cuhepy

<p><strong>GPU-accelerated homomorphic encryption in Python.<br>
Paillier and BFV, with encrypted nearest-neighbour search as the worked example.</strong></p>

<p>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-2e6cc4" alt="License"></a>
  <img src="https://img.shields.io/badge/status-experimental%20research-orange" alt="Experimental">
</p>

</div>

---

> [!WARNING]
> **Experimental research code. Not audited, not constant-time, and not suitable
> for protecting real data.** Both schemes are implemented from scratch for
> study and measurement. We publish the attacks we found against our own code in
> [`attacks/`](./attacks) and [`docs/research/`](./docs/research) — read those
> before trusting anything here.

## What this is

Two homomorphic encryption schemes, each with a CPU reference implementation in
Python and optional compiled backends:

| | Scheme | Backends | Homomorphic over |
|---|---|---|---|
| **`cuhepy.paillier`** | Paillier, plus an α-subgroup variant with precomputed tables | pure Python/GMP · **CUDA** | addition |
| **`cuhepy.bfv`** | Leveled BFV over `Z_q[X]/(X^N+1)`, SIMD batching | pure Python/GMP · cached GMP · **C++ RNS/NTT** | addition, multiplication, rotation |

`cuhepy.paillier` and `cuhepy.bfv` are the primitives — key generation,
encryption, decryption and the homomorphic operations, over arbitrary integers.

`cuhepy.hamming` is an application built on top: **encrypted k-nearest-neighbour
search**, where an evaluator holding only the public key ranks encrypted vectors
by Hamming distance without learning the vectors, the query, or the distances.
It is the workload the compiled backends were originally written for, and it is
kept separate from the schemes so neither depends on the other.

## Install

```bash
pip install cuhepy
```

Requires Python 3.11+. The CPU path has four dependencies (`gmpy2`, `msgpack`,
`numpy`, `pycryptodome`) and needs no GPU. Compiled backends are opt-in — see
[Compiled backends](#compiled-backends).

## Quick start

Encrypt two vectors, let an untrusted evaluator compute their Hamming distance
on the ciphertexts, and decrypt the result:

```python
from cuhepy.hamming.paillier_lookup import PaillierLookupClient

client = PaillierLookupClient(embed_len=512, key_len=1024)

a = [i % 2 for i in range(512)]
b = [(i // 2) % 2 for i in range(512)]

# Client side: encrypt. Only these ciphertexts leave.
ct_a = client.encrypt_vec_one(a)
ct_b = client.encrypt_vec_one(b)

# Evaluator side: public key only, one modular multiply per chunk.
ct_distance = client.encode_hamming_server(ct_a, ct_b)

# Client side: decrypt.
assert client.decode_hamming_client_one(ct_distance) == sum(x ^ y for x, y in zip(a, b))
```

Persist the keypair with `cuhepy.keys` (writes the secret key in plaintext at
mode `0600` — key management is deliberately out of scope):

```python
from cuhepy import keys

keys.save(client, "key.json", include_tables=True)
restored = keys.load("key.json")
```

The schemes are also usable directly, without the Hamming layer:

```python
from cuhepy.paillier.scheme import Paillier

kp = Paillier.key_gen(1024)
c = Paillier.add(Paillier.encrypt(7, kp["pk"]), Paillier.encrypt(35, kp["pk"]), kp["pk"])
assert Paillier.decrypt(c, kp) == 42
```

## Cost

Per 512-dimensional binary vector, single CPU thread, `key_len=1024`. The two
schemes put the cost in different places, which is the whole reason both exist:

| | encrypt | evaluate | decrypt | response bytes |
|---|---|---|---|---|
| Paillier | 6.9 ms | 3 µs | 4.6 ms | 512 B / vector |
| Paillier-Lookup (α=280) | 0.5 ms | 3 µs | 0.66 ms | 512 B / vector |
| BFV, packed | — | ~2.4 ms | ~constant per query | ~100–200 KB total |

Paillier is cheap for the evaluator and expensive for the client, whose work
grows linearly with the corpus. BFV inverts that: the evaluator does real work,
but packs many distances into one response ciphertext, so the client decrypts
once and the response stops growing. Raw numbers and the harness are in
[`benchmarks/`](./benchmarks) and [`docs/research/`](./docs/research).

## Threat model

The evaluator receives the public key, the encrypted index and encrypted
queries. It never receives the secret key.

**Hidden:** vector contents, query contents, the computed distances.
**Visible:** how many vectors exist, which one was queried, when, and any
plaintext metadata the caller chooses to attach.

These schemes are secure against an **honest-but-curious** evaluator — one that
follows the protocol and only observes. Against a **malicious** evaluator that
crafts ciphertexts and watches how the client reacts, both are broken, and we
demonstrate it:

- **PL-01** — the α-subgroup variant's secret key is recoverable from the public
  key if α is too short. At the old 50-bit default: ~3.5 minutes on a laptop.
  Fixed (α ≥ 256 enforced); the demonstration is kept as a regression.
- **PL-04** — a malicious evaluator recovers stored bits by watching which
  result the client fetches.
- **BFV-01** — a decryption oracle recovers the BFV secret key from accept/reject
  feedback.

`cuhepy.bfv.guarded_client`, `verified_client` and `attested_client` are
experimental protocol layers that address BFV-01 at a trust and compute cost.
Full write-ups: [`docs/research/paillier-security.md`](./docs/research/paillier-security.md)
and [`docs/research/native-bfv-security.md`](./docs/research/native-bfv-security.md).

## Compiled backends

Both are optional; the pure-Python path works without them.

**CUDA (Paillier)** — builds inside a pinned `nvidia/cuda` container, so the
build host needs only Docker, not a GPU or a local CUDA toolkit:

```bash
./build_gpu_binaries.sh      # -> src/cuhepy/paillier/_{,lookup_}gpu_ext/*.so
```

Runtime needs an NVIDIA driver ≥ 550 and a GPU of compute capability 7.0–9.0.
Clients probe for the extension at construction; `device="cpu"` or `device="gpu"`
forces a backend.

**C++ RNS/NTT (BFV)** — `make -C src/cuhepy/bfv/_cpu_ext`. Select it with
`BFVClient(server_backend="rns" | "native" | "residue")`.

## Verify it yourself

Everything runs offline, no account or service required:

```bash
uv sync --all-groups
uv run pytest tests/                                  # full offline suite
uv run python attacks/pl01_alpha_recovery.py          # recover a key from a public key
```

## Repository layout

```
src/cuhepy/
  paillier/   scheme.py · lookup.py · _gpu_ext/ · _lookup_gpu_ext/    ← primitives
  bfv/        scheme.py · evaluator.py · rns.py · native.py · _cpu_ext/
  hamming/    base.py · paillier.py · paillier_lookup.py · bfv.py     ← application
  base.py  device.py  keys.py  types.py  bench.py
attacks/      runnable demonstrations of the findings above
benchmarks/   measurement harness and recorded results
docs/research/ security reviews and optimisation reports
experiments/  SEAL cross-check, Nitro enclave evaluator
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Findings against the schemes are
especially welcome — that is what this repository is for.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
