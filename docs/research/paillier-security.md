# Paillier & Paillier-Lookup security review

Source review of the Paillier and Paillier-Lookup schemes and their Hamming
client, with runnable regressions. This is an AI-assisted internal review, **not**
an independent audit or a proof of security.

**Trust model.** The data owner holds a trusted client and the secret key. An
evaluator receives the public key, the encrypted index, and encrypted queries,
and computes encrypted Hamming distances homomorphically. Two adversaries are
considered: an *honest-but-curious* evaluator that follows the protocol and only
observes its inputs, and a *malicious* evaluator that may craft, replay or
reorder ciphertexts and observe the client's subsequent behaviour (which result
is fetched, whether decoding succeeds). The schemes target confidentiality
against the honest-but-curious model only; PL-04 marks where the malicious model
breaks it.

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| PL-01 | Critical | Secret key recoverable from the public key at `alpha_len=50` | Demonstrated — **fixed** |
| PL-02 | High | Static `PaillierLookup.encrypt` is deterministic without a noise table | Confirmed |
| PL-03 | Medium | Lookup randomizer entropy is ~80 bits regardless of `alpha_len` | Confirmed |
| PL-04 | High | Malicious evaluator recovers stored bits via a ranking/decode oracle | Analysed |
| PL-05 | Medium | Client constructors skip the `embed_len < key_len` guard | Confirmed |

---

## PL-01 — secret key recoverable from the public key (`alpha_len=50`)

**Severity: Critical.** The α-subgroup variant publishes `g_n = g^n mod n^2` in
the public key. Its multiplicative order is exactly `a = lcm(q1, q2)`, an
`alpha_len`-bit integer, and `PaillierLookup.decrypt` uses only `a` (never
`phi`). Baby-step/giant-step recovers `a` in ~`2**(alpha_len/2)` group
operations; with `a` and the public key, any ciphertext decrypts.

The CPU client default was `alpha_len=50`, i.e. ~2**25 work.

**Demonstrated** (`attacks/pl01_alpha_recovery.py`):

```
alpha_len=40, key_len=512:   recovered a in 2.9s,  pk-only decrypt OK
alpha_len=50, key_len=1024:  recovered a in 204s (123s baby + 81s giant), pk-only decrypt OK
```

So the old CPU default was breakable in ~3.5 minutes on a laptop from the public
key alone.

**Fixed.** `DEFAULT_ALPHA_LEN = 280`, matching the `ALPHA_LEN` the CUDA
extension is compiled with, so CPU- and GPU-generated keys stay interchangeable.
`MIN_ALPHA_LEN = 256` is enforced in `PaillierLookupClient.__init__` when
generating a keypair; `allow_weak_alpha=True` opts out for cryptanalysis.
Loading an existing weak keypair warns (`RuntimeWarning`) rather than failing,
so old material can still be read and re-keyed. The raw `PaillierLookup.key_gen`
primitive stays unguarded — `attacks/` depends on it.

Measured cost of the change: decode 0.15 → 0.66 ms/vector; encryption and
key generation unchanged. Regressions in
`tests/unit/test_paillier_lookup_encryption.py`.

---

## PL-02 — deterministic static encryption without a noise table

**Severity: High.** `PaillierLookup.encrypt(plaintext, pk)` defaults
`noise_table=[mpz(1)]`, so with no table the ciphertext is the deterministic
`g^m mod n^2` — identical plaintexts yield identical ciphertexts, and an
evaluator can equality-test stored and query vectors. The client path always
passes a real table, but the static API silently produces unrandomized
ciphertexts.

**Fix.** Make the noise table (or a fresh `r^n` factor) mandatory; raise rather
than default to the identity.

---

## PL-03 — bounded randomizer entropy

**Severity: Medium.** When a noise table is used, randomization multiplies 14
(`NOISE_MULTIPLES`) entries drawn from a 256-entry table (`NOISE_TABLE_SIZE`),
i.e. ~`log2(C(256+14,14))` ≈ 80 bits, independent of `alpha_len` or `key_len`.
This is a BPV-style tradeoff and should be a documented, configurable parameter
sized against the security target rather than a constant. Separately,
`PaillierLookup.encrypt` computes `generate_random_r(...)` and then discards it —
dead code that misleadingly suggests per-encryption `r^n` randomization.

---

## PL-04 — ranking/decode oracle under a malicious evaluator

**Severity: High (malicious model).** The Hamming encoding packs each bit as a
`0 b` pair and `decode_hamming_client` sums the odd-position bits of the
decrypted chunks. A malicious evaluator that can submit chosen ciphertexts and
observe the client's response (which id ranks first, or whether decoding lands
in range) learns plaintext bits of stored vectors: homomorphically add a known
offset to a single slot and compare the resulting rank or decode outcome. This
recovers *data* rather than the key, but is a full confidentiality break against
a dishonest evaluator.

**Fix direction.** Authenticated, one-use queries and an owner-side verified
result before any client action becomes observable. Out of scope for the
honest-but-curious target; documented as a known limit.

---

## PL-05 — constructors bypass the dimension guard

**Severity: Medium.** `PaillierClient(embed_len=..., key_len=...)` and
`PaillierLookupClient(...)` accept `embed_len > key_len`. The chunk width
`2*key_len` can then exceed the modulus `n` (which may be as small as
~`2**(2*key_len-2)`), so the padded plaintext wraps mod `n` and the homomorphic
sum silently corrupts — a data-dependent wrong distance rather than an error.

**Fix.** Enforce `embed_len < key_len` in the client constructors.

---

## Reproduction

```bash
uv run python attacks/pl01_alpha_recovery.py            # alpha_len=40, ~3s
uv run python attacks/pl01_alpha_recovery.py 1024 50    # former CPU default, ~3.5min
```

At the current default (`alpha_len=280`) the same search needs ~2**140
operations and is infeasible.

PL-02, PL-03 and PL-05 are direct API observations; PL-04 is analysed, not yet
scripted.
