# Q76.4 product-control adaptation card

The exact aggregate control is now implemented in the bounded scope below.
The randomized adaptation remains a prospective design; neither is a measured
speedup or an originality claim. It follows the selected owner-canonical shared
query graph, actual Q120 primes, original signed inputs and complete frame.
It does not change Q76.3b's running one-key/six-search correctness cohort.

That earlier source cohort and the later
[prepared replay gate](native-shared-query-replay-20261004.md) now pass. The
[aggregate registration](native-shared-query-aggregate-registration-20261004.json)
selects the exact three-product control. Its later
[implementation return](native-shared-query-aggregate-20261004.md) passes the
registered local/public gate; timings remain absent. Comparing the three tensor coefficient vectors directly with
the equally optimized paired-Karatsuba aggregate is the coefficient form of
the exact three-point identity and avoids gratuitous scalar overhead. It still
pays all three protected products, prefix preparation/residency and the suffix.
If this matches or loses to full protected replay, retain that result; the
control is not required to produce a positive delegation headline.

The closest mechanism is [vFHE Appendix D](https://arxiv.org/html/2301.07041v2#A4):
it checks ciphertext tensor products by evaluating their component polynomial
at a hidden scalar, replacing several ring products with one. Our adaptation
must cover the aggregate feature sum and still pay trusted query expansion,
maintenance, terminal conversion, input binding and release. This reading
does not reproduce the author artifact or benchmark.

## Exact aggregate to check

Let `X[j]` be the genuinely expanded two-component query and `I[g,j]` the
authenticated prepared index. For each group the untrusted evaluator claims
three **pre-relinearization** whole-Q polynomials `C[g,0:3]`. The claim is

```text
C0 = sum_j X[j,0] * I[g,j,0]
C1 = sum_j (X[j,0] * I[g,j,1] + X[j,1] * I[g,j,0])
C2 = sum_j X[j,1] * I[g,j,1]
```

Products are negacyclic ring products. At scalar `a`, the checker compares
`C0 + a*C1 + a*a*C2` with
`sum_j (X[j,0] + a*X[j,1]) * (I[g,j,0] + a*I[g,j,1])`.
This checks the required aggregate; individual feature products need not be
proved if their sum is the only downstream input. Compare the **entire**
vector in each actual prime NTT. This is not sampling one NTT coordinate.

The trusted prefix must derive `X` from the authenticated original seeded
query using genuine canonical expansion. A peer-supplied expanded query is
not a free input. The trusted suffix receives the checked aggregate, performs
canonical delayed relinearization and exact Q-to-P conversion, and binds the
complete frame/ordered IDs to the journal authorization. Validate complete
canonical common-Q syntax before using a claimed aggregate; the producer
cannot supply independent digit decompositions in the two primes.

## Assurance changes the operation comparison

Our analysis of this degree-two aggregate gives the following registered
alternatives. The exact control has passed its registered local/public correctness gate.
Randomized alternatives and full protocol composition remain unreviewed proposals.

| Control | Algebraic guarantee and required premise | Protected aggregate products per feature |
| --- | --- | --- |
| One fresh hidden point per actual prime | For a fixed incorrect aggregate, at most `2/min(p_i)` false acceptance; complete vectors and commitment before challenge are essential. | One, plus scalar operations and sums. |
| Three independent hidden rounds | At most `B*(2/min(p_i))^3` over `B` adaptive consumed attempts, under fresh hidden randomness and a non-rollback global budget authority. For the proposed `B <= 2^32`, this is below `2^-128`; it is not HE security approval. | Three, plus all rounds' scalar operations and sums. |
| Three distinct points `0,1,-1` | Exact equality of the degree-two aggregate: interpolate each coefficient/NTT coordinate. Both actual primes are odd, so division by two is defined. No statistical challenge error. | Three, plus scalar operations and sums. |
| Equally optimized paired Karatsuba/replay | Compute the three aggregate coefficients directly and compare or return them inside the protected computation. | Three, plus additions and sums. |

The exact three-point argument is elementary. If a claimed difference has
coefficients `(e0,e1,e2)`, its values are `e0`, `e0+e1+e2`,
`e0-e1+e2`. All three zero imply `e0=0`, `2*e1=0`, `2*e2=0`.
Two is a unit in each actual prime and in the whole odd-Q ring. Complete
zero comparisons therefore force all three coefficient polynomials to zero.
This is a known interpolation identity, not a new cryptographic primitive.

For the probabilistic cases an incorrect whole-Q aggregate has a nonzero
degree-at-most-two error at some coordinate of at least one actual prime.
That coordinate suffices for the root bound. Do **not** multiply the two
prime failure probabilities: an adversary can change only one limb. Commit
the immutable claimed aggregate before drawing fresh scalar challenges;
the server must not observe them or modify the buffers afterward. A selected
error that remains wrong only at an omitted coordinate is not covered by
sampling instead of the complete-vector comparison.

Three-round amplification can consume the one-product advantage relative to
the equally optimized three-product baseline. This operation-count observation
does not establish which full service is faster: prefix/suffix work, memory
traffic, fusion, preparation, transfers and reuse must be measured. It also
does not reject a correctly labeled one-round lower-assurance experiment.
Do not claim to defeat the published optimization by comparing its stronger
assurance adapter with an unoptimized four-product control.

## Handoff and paid costs

Implement prepared replay first in the same native backend. It may return the
complete frame without serializing a peer witness it does not need; skipping
those writes cannot skip internal canonical source formation. Charge the same
cached/streamed inputs, maps, keys, origin checks, lifecycle and terminal codec
to every compatible control.

Then implement the deterministic checked-product/trusted-prefix/suffix seam
and decide the probabilistic scope explicitly. An aggregate-only canonical
whole-Q witness is `3*groups*N*15` bytes, or 1,474,560 bytes at two groups;
this is an internal server-to-protected-verifier witness, **not** the compact
client response or a measured communication ratio. Count both link directions,
trusted expanded-query residency, producer work and suffix/release work.

Required tests include all aggregate coordinates in both primes, a one-limb
fault, component cancellation in an insufficient one-point check, incorrect
query/context/IDs, late grammar, common-Q syntax, suffix and complete-frame
faults, and the same state/replay boundary. An unsigned local test adapter
does not establish a deployed TEE or a global hidden-challenge budget.

Return this card to the [execution plan](system-contribution-execution-plan-20261004.md).
The potential paper result remains a useful, prior-separated **complete-cost
design choice** and its assurance argument. Product interpolation, TEE-assisted
HE, feature packing and ordinary planner selection remain known ingredients.
