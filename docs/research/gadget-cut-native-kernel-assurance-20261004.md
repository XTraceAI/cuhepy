# Conditional native equality argument and unfinished release contract

This is an argument for the public research primitive, **not a reviewed
production security proof**. The native arithmetic and common-Q wire components
have the [recorded small correctness scope](gadget-cut-fusion-results-20261004.md).
The complete release/network controller is not implemented by these components.

Assume actual distinct primes p0,p1, Q=p0*p1, power-of-two N, primitive2N-th
roots in each field, correct compiled equations/arithmetic, authentic owner
index/query/keys, and the enrolled public Q/P bounds. Primality/root/parameter
assurance and implementation review remain obligations; probable-prime checks
and toy tests are not independent parameter certification.

## Exact equality lemma

For `R_Q=Z_Q[X]/(X^N+1)`, CRT identifies a polynomial with its two prime-field
images. In each field the NTT evaluates at all N distinct odd powers of the
primitive2N-th root. This is an invertible linear map. Therefore

`r=0 in R_Q` iff every NTT coordinate of r is zero in **both** fields.

The kernel evaluates each complete residual with modular operations, signed
monomials and enrolled odd automorphisms, then tests every resulting coordinate.
It does not evaluate at only one root. A nonzero ring polynomial can vanish at
some roots or in one entire CRT limb; those facts do not authorize acceptance.
The targeted regressions retain both cases. No random-weight soundness term
or challenge-reuse assumption is needed for this deterministic primitive.

At the C++ arithmetic boundary p<2^60. Each scalar/product uses unsigned128-bit
arithmetic; addition/subtraction of canonical field values fits64 bits.
NTT lazy-range/root-map correctness belongs to the reused homemade implementation
and must still receive its own review. Testing sampled vectors does not prove
the entire C++ implementation correct.

## Relation and common-lift lemma

The original relation is acyclic. A canonical source is one common integer
polynomial in `[0,Q)`. Its unique radix digits are derived from those bytes,
not supplied separately for each prime. The source equation fixes it to the
virtual predecessor expression. Tensor C2 is constrained to original encrypted
inputs; all C0/C1 corrections, plus/minus branches, unary zeros and rotations
remain in the graph. Induction then fixes both terminal-Q components, including
unused coordinates.

Derived digit families are deterministic recipes over those common digits and
the enrolled public key/index digit families. They have no independent witness.
Bound replay applies to that original integer recipe. The fused checker may
reduce public composites modulo Q: it computes the same Q result, so it does
not authorize a different secret-dependent lift or relax the original bound.
This is ordinary public linear elimination; no new gadget or proof primitive
is claimed.

Authentic owner origin is essential. A server-selected phase bound, key,
index/query ciphertext, plan or primitive root cannot supply this premise.
The current small compiler checks its enrolled conservative bound before
building the graph. A production controller must preserve that trust boundary.

## Conditional public-admission coupling

Suppose a complete trusted controller also binds snapshot, ordered IDs, epoch,
original query, keys/primes/order/plan, count/tails and the exact full response.
After the equality check it must construct the authoritative congruent nearest-
lift terminal frame from those verified Q outputs and require complete equality
with a claimed frame, before any private decoder or signer is reached.

Under the bound/origin premises, accepted outputs are the specified honest
evaluation and have deterministic decryption validity. The public admission
predicate uses no secret key. A simulator with the server-visible ciphertexts,
keys and enrolled public context can compute the same accept/reject predicate.
Thus observing that predicate adds no secret-key oracle beyond those public
inputs. Coupling to ideal public admission is exact **conditional on** the
deterministic implementation and complete release contract. Confidentiality of
the original inputs/evaluation keys still needs the actual augmented HE
assumptions; this is not a new CCA theorem for raw malleable BGV.

Verifying before private decryption and correct/honest-evaluation notions are
known controls: see the retained [vFHE](https://arxiv.org/html/2301.07041v2),
[vCCA](https://eprint.iacr.org/2024/202) and
[exact-FHE CPAD analysis](https://eprint.iacr.org/2024/127) readings in the
[closest-work comparison](closest-work-system-blueprint-20261003.md). Their
theorems, parameters and implementations are not automatically transferred to
this prototype. This conditional argument is supporting analysis, not a
prior-separated contribution or a completed reduction for the deployed system.

## What remains before claiming that coupling for a service

The native wire primitive fixes query bytes and source/output slots, but has no
network context/epoch/ID/request header or signer. Its Python factory is a small
diagnostic; a caller-supplied arbitrary graph is not an authorized statement.
Production enrollment must compile the authoritative owner relation internally,
freeze all input/parameter/key bytes and expose no alternative graph/weight path.

Implement exact terminal-frame equality, failure-before-release, sealed request
ownership, concurrency/copy/fork/process lifetime, authoritative update/freshness
and attested code/state binding. Current immutable kernel copying and process
guards address pointer ownership only; they are not a global replay/update
controller. Deterministic exact checking has no false-accept attempt budget,
but global origin/enrollment/lifetime limits and cryptographic security budgets
remain. Private timing/cache/memory leakage and attestation/deployment assurance
remain separate. There is no private operation in either native kernel.

The next construction must make those interfaces concrete and test them with
HE expected-response/private APIs unavailable. Source-scale enrollment,
preparation, producer/tape costs, roots/maps/scratch, updates and the equally
rewritten replay/cache controls then decide usefulness. A successful equality
primitive alone establishes none of those performance or deployment claims.
