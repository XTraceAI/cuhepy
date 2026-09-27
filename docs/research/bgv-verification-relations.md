# BGV verification boundary and arithmetic relations

This begins E13/E14 on `experiment/bgv-verification-packing`, after the saved
baseline in [PR #14](https://github.com/XTraceAI/cuhepy/pull/14). It specifies
what a verifier would need to establish and identifies an expensive initial
partition. It is **not** an authenticated GPU implementation or a proof system.
The current CPU Nitro protocol and raw CUDA experiments retain their respective
trust boundaries. The [literature agenda](encrypted-search-literature-agenda.md)
contains the prior work, soundness assumptions and broader comparison contract.

## Complete statement

An eventual receipt or proof must bind the owner, index epoch, ordered encrypted
index commitment, key/parameter commitment, session and one-use request ticket,
query bytes, result bytes, vector count, dimension/layout, and evaluation and
compression policies. The new
`cuhepy-lab-bgv-joint-support-bound-v1` must be bound explicitly if selected.
Neither a phase bound nor a successfully decoded distance authorizes decryption.

An index commitment must bind ordered tiles and their valid counts, including
padding. Proving that each selected tile belongs to an index does not establish
that all required tiles were processed once. The statement must connect the
exact output bytes to the complete prescribed search, before private processing.

## Actual evaluator stages

This inventory follows `NativeServer`, `GPUWorkspace`, `cuda_trace.cuh`,
`terminal_cuda.cuh`, and the query/response codecs. A row cannot simply be omitted
because neighboring stages have valid linear checks.

| Stage | Relation or trusted work | Context/representation that must be bound |
|---|---|---|
| Query envelope and expansion | Canonical parse, fresh seeded uniform component, congruence-preserving c0 expansion | Exact packet, key ID, seed-stream domain, codec version, drop count and allowed bound |
| Prepared index | Canonical ciphertexts; all ordered tiles from the committed epoch | Count, zero padding, public parameters, preprocessing provenance; no duplicate/omitted/reordered tile |
| RNS conversion and forward NTT | Canonical residues and the prescribed negacyclic transform in **each** limb | RNS prime, root, coefficient order and scale; the two limbs are one integer ciphertext |
| Query/index tensor product | For every coordinate, `(a*x, a*y+b*x, b*y)` for query `(a,b)` and index `(x,y)` | Both components, every tile, same request/epoch; linear in query only when index is fixed |
| Inverse NTT | Inverse transform including `N^-1` and untwist | Full canonical output, matching prime/root/order |
| Relinearization input | Canonical CRT reconstruction of c2, then four base-2^30 digits | Range **and** integer recomposition; digits correspond to the actual preceding tensor |
| Gadget key multiplication | Transform each digit, multiply by the fixed evaluation-key pair, accumulate and invert | All digit columns, both output components, key ID and correct switch key |
| Initial monomial shift | Negacyclic signed permutation by `1-D` | Exact coefficient sign and location |
| Joint butterfly | Plus/minus, automorphism, then canonical CRT/digits and the matching key switch at every level | Active tail shape, level exponent/key, all dependency edges; repeat nonlinear digit constraints at every switch |
| Terminal conversion | Canonical CRT and the exact integer quotient/rounding relation below | Q, P, t, both components, entire output polynomial, selected public bound policy |
| Response compression | Existing deterministic c0 map; unchanged c1 | Canonical coefficients and holes, drop count, full framed count/layout, strict no-wrap bound |
| Final authorization | Complete evaluated output commitment plus replay/lease policy | No private parsing/decryption before successful authorization; no unchecked output bytes |

An NTT, fixed-index tensor product, or fixed-key multiply admits a field-linear
check. Canonical CRT lifts, gadget digits, integer rounding and packet grammar
do not follow from such a check. Individual verified stages also need commitments
or a trusted path connecting their inputs and outputs.

## Exact integer relations

For canonical `0 <= c < Q`, terminal conversion uses `r = c mod t` and

```
A = 2*P*c - 2*Q*r + Q*t
B = 2*Q*t
B*k <= A < B*(k+1)
output = (k*t+r) mod P,  0 <= output < P.
```

The strict upper inequality fixes the floor and its tie rule. k can be negative:
small positive c with nonzero r can give k=-1. An unsigned-only relation would
reject valid arithmetic. `0 <= r < t` and `c = r (mod t)` must also be enforced.
A field equality alone allows an incorrect quotient or a representative shifted
by the proof field modulus. A proof backend needs sufficient integer widths and
range constraints; Python's unbounded integers are just a reference semantics.

For gadget base `beta=2^b`, require exactly `ceil(bitlength(Q)/b)` digits,
`0 <= d_j < beta`, and `c = sum_j d_j*beta^j` **as integers**, with `0 <= c < Q`.
Range-free recomposition accepts, for example, adding beta to a lower digit and
subtracting one from the next digit. Modular recomposition has additional aliases.
CRT similarly requires `0 <= c < product(p_i)` and canonical residues in every
limb; congruences alone do not select the canonical integer needed by rounding.

## Cost of putting every digit conversion inside the trusted CPU

This is a deliberately simple boundary model, derived from the actual joint
schedule. Each key switch consumes N canonical coefficients for decomposition.
There is one relinearization per index tile and one switch per active butterfly
node. For each response group containing K tiles, the number of butterfly
switches is `sum_(j=1..log2(D)) min(K, D/2^j)`.

At N=16,384, D=512, Q120, four 30-bit digits and two 60-bit RNS limbs:

| Vectors | Index tiles | Butterfly switches | Total switch-input coefficients | Native-layout round trip | Ideally bit-packed round trip |
|---:|---:|---:|---:|---:|---:|
| 8,192 | 256 | 511 | 12,566,528 | 1,005,322,240 B | 376,995,840 B |
| 32,768 | 1,024 | 1,022 | 33,521,664 | 2,681,733,120 B | 1,005,649,920 B |

Native-layout traffic counts 16 input bytes per coefficient (two uint64 RNS
limbs) plus 64 output bytes (four uint64 digits replicated in both limbs),
matching `write_digits`. Ideal packing counts 15 bytes each for the reconstructed
input integer and four 30-bit digits. Sending each digit once as uint64 and
duplicating on the GPU lies between these: 48 bytes per coefficient.

These are **modeled internal CPU/GPU bytes**, not measured link traffic or
latency. They exclude transform-check traces, commitments, terminal conversion,
index updates and preprocessing. Packing requires additional work and proof of
its connection to the input residues. A verifier that receives unverified digits
cannot avoid that connection just by checking digit ranges.

The simple partition therefore moves hundreds of MB to multiple GB per request,
despite the owner/client response being around 80–156 KB. It deserves a transfer
and trusted-CRT microbenchmark before implementing a complete service. It is not
yet evidence that verified GPU evaluation must lose: batched relation proofs,
better partitions, and genuinely attested GPU execution remain alternatives.

## Field-check contract

For a committed proposed `y=A*x` over a prime field, trusted preprocessing with
a fresh hidden uniform r computes `u=A^T*r`. The check is `r^T*y=u^T*x`. A fixed
nonzero error escapes with probability exactly 1/p for one check. h independent
checks yield `p^-h`; a lifetime bound must include every checked stage/request.

Check every RNS limb. Corrupting one limb gives only that limb's detection bound;
honest equations in other limbs do not multiply its soundness. Full vector
uniformity matters: choosing powers of a single challenge instead requires a
different polynomial-degree bound.

The verifier must check the committed output, not a GPU-provided checksum.
Keep r hidden until the relevant output is fixed. Consume preprocessing on every
attempt, including rejection or retry, and bind it to the stage and statement.
Charge trusted generation, storage and refill. The tiny arithmetic oracles do
not implement these protocol obligations, transcripts, attestation or receipts.

## Executable references

[`verification_oracles.py`](../../experiments/bfv_search_lab/verification_oracles.py)
implements independent Vandermonde NTT matrices, the field identity with all
trusted preprocessing included, exact CRT/gadget/terminal integer relations,
and the switch-count/traffic model. Toy fields are deliberately limited to
p≤65,521. This is an explicit arithmetic oracle, with no network/client API,
challenge generator or reusable verification material.

The [tests](../../experiments/bfv_search_lab/test_verification_oracles.py) exhaust
all challenges for every nonzero error in several two-dimensional small fields;
confirm the 1/p miss count; demonstrate the single-corrupted-limb and known-
challenge pitfalls; compare direct NTT evaluation with the existing radix-two
transform; and check fixed-index tensor linearity. They exhaust more than
100,000 small terminal coefficients, rejecting incorrect quotients, residues
and outputs, including negative quotients, an exact rounding tie and a proof-
field alias. Gadget/CRT tests reject range-free and noncanonical aliases.
Traffic counts are cross-checked against the existing butterfly schedule,
including partial and multiple response groups.

```bash
.venv/bin/python -m pytest experiments/bfv_search_lab/test_verification_oracles.py -q
```

Next, measure the modeled boundary, choose a complete small statement, and
compare a trusted nonlinear core with a reviewed proof backend. Continue only
after mutations of every stage, context and coverage rule are rejected and the
complete costs are measured. There is no claim of an efficient verified GPU
service from these arithmetic identities alone.
