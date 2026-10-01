# E73: packed encrypted CRT queries and the verification boundary

2026-10-01. R3-B0's [preregistered](query-verification-preregistration-20261001.md)
control is implemented in homemade
[arithmetic](../../experiments/bfv_search_lab/packed_query_expansion.py),
[tests](../../experiments/bfv_search_lab/test_packed_query_expansion.py) and
[runner](../../benchmarks/packed_query_expansion_lab.py). Immutable
[raw](../../benchmarks/results/publication-packed-query-expansion-control-20261001.json).
No Microsoft HE implementation is imported.

## Exact mechanism and attribution

For column j's query polynomial b_j, pack `sum_j X^j b_j(X)/H mod t`.
H is a power of two at least the number of columns and must divide every
declared subring stride. Its log2(H) expansion levels select coefficient
residues; they do not reduce the degree-N encryption ring or secret.

At level l, apply automorphism `X -> X^(1+N/2^l)`, key-switch its secret back
to s, add/subtract, and shift the odd branch by `X^(-2^l)`. Predivision by H
avoids a large plaintext normalization after expansion. Discard only publicly
padded columns. Full-field components and all multiplication cross terms are
preserved. For fresh bound F and switch bound S:

```
expanded bound = H F + (H-1) S
reply bound    = N * number_of_columns * F * expanded_bound
```

This is a **known query-expansion control**. [SealPIR §3.3/Appendix A](https://eprint.iacr.org/2017/1142.pdf)
supplies coefficient expansion; [Ali et al. §3.1–3.2](https://www.usenix.org/system/files/sec21-ali.pdf)
already describe secret-key seeded queries, pre-normalization and joint
packing. Partial expansion here adapts those ingredients to existing CRT
column supports. Those ingredients and their composition are not credited as
an original contribution. No paper performance figures are transplanted to
our search workload, and no author HE code is imported.

## Verification is not free

An E72 multiplication check on **server-supplied expanded queries** proves
the wrong statement if the server changes those inputs. A regression adds a
plaintext constant to one expanded query: the naive adapter accepts a changed
score while its multiplication relation is perfectly correct. This tests an
unsafe adapter, not a defect in E72's trusted-original-input contract.

The valid control locally expands the client's own original ciphertext and
pins that exact deterministic expansion before checking the server reply. It
rejects the substitution. This charges an expansion to **both client and
server**. There is no succinct expansion certificate here. A proposal must
certify the entire automorphism/gadget/carry circuit or pay that client work;
linearity of the plaintext mapping does not make canonical key switching
field-linear in ciphertext coefficients.

## Evidence and complete costs

112 packed queries and 112 unpacked controls use the **same full-degree toy
key, encrypted index, N=32, Q32, t=17, eta=1**. Scores and stable IDs agree.
Independent ordinary products verify C0/C1/C2. Tests additionally check 32
mixed-degree/non-power-of-two-column expansions, residue alias rejection,
keys, bounds and the substitution gap. **12 E73 + 18 E72 tests pass**, no skips.

Actual query packets shrink **924 -> 231 B (4x)**. Response bodies have the
same 288–1,048 B support sizes at this same Q. Extra public switch-key body:
**4,096 B**; 3 switches/48 ring products per expansion. The coefficient-body
setup amortization is nine queries; actual packet savings amortize this key
body in six queries, excluding the key envelope/transport.

Toy medians: packed query encryption 0.152–0.186 ms, **trusted client expansion
1.171–1.202 ms**, server expansion 1.151–1.185 ms and server index product
0.857–1.513 ms. Same-run unpacked query encryption is 0.360–0.401 ms and its
server product 0.402–1.059 ms. Timings include public shape/key/bound validation;
these are research Python/GMP stages, not kernel timings or service/security
equivalent performance claims. Independent diagnostic products are excluded.

Separate eight-profile **worst-case correctness/count screens**, not large
ciphertext runs, stabilize at 69–77-bit Q with 4-bit unsigned gadgets. Selected
Mushroom/Semeion each need a 26,542,080 B unseeded switch-key body and 1,116
products per expansion, versus 96/69 index products. Raw Connect-4 needs
4,515,840 B keys, 4,572 expansion products versus 6,048 index products. Every
screen exceeds a single 64-bit modulus; this identifies a cost for RNS or a
different noise/gadget analysis, not a proof that every packing variant needs
that Q. Keys/index must be replaced. No parameters or related-secret security
have been approved.

## Return to R6

**Keep the control, stop unchecked expansion and the literal combined variant
as a paper candidate.** Query upload falls, but expansion work, larger Q,
private checks and setup remain. Packing alone supplies neither originality
nor a safe low-state verifier. Return to a genuinely carry-aware R3-A0 or
succinct R3-B1 construction. R4's programmed-correlation alternative is worth
a bounded structure-aware screen; compare the actual small block coordinate
factory, not an artificially dense plaintext matrix. R2's matched cache/HE
acquisition remains required before any useful-system selection.

```bash
.venv/bin/python benchmarks/packed_query_expansion_lab.py \
  --json-out /tmp/e73-new-run.json
```
