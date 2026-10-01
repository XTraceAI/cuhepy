# E70: coefficient-field quotient certificates and unsafe shortcuts

2026-09-30. Bounded primitive experiment proposed in the
[mechanism review](publication-mechanism-review-20260930.md), not an implemented
replacement for the owner factory. Homemade
[oracle](../../experiments/bfv_search_lab/convolution_certificate_oracle.py),
[tests](../../experiments/bfv_search_lab/test_convolution_certificate_oracle.py),
[runner](../../benchmarks/convolution_certificate_lab.py) and
[raw](../../benchmarks/results/publication-convolution-certificate-screen-20260930.json)
at source HEAD `9886e3a`.

## Identity and independent controls

For degree-<N factors, the prover can return c of degree <N and quotient h of
degree <=N-2, with

```
sum_j a_j(X)b_j(X) = c(X) + (X^N+1)h(X) over F_Q[X].
```

Checking this at a uniform coefficient-field point is known polynomial
identity testing. On 81 N=2 products all 1,377 field-point checks pass. Three
N=8/16/32 batch cases pass another 547 checks, with an independent
cyclic/negacyclic quotient reference. If ordinary cyclic product is c_plus
and negacyclic product c_minus, h=(c_plus-c_minus)/2 on coefficients 0..N-2.
This known relation identifies an additional product/transform cost rather
than treating quotient generation as free. No native/GPU timing is measured.

## Exact shortcut counterexamples

1. **Sample only NTT roots:** a deliberate degree-7 output error in the N=8,
   Q=97 example vanishes at seven of eight negacyclic roots. A one-root check
   accepts that wrong answer **87.5%** of the time. Using the quotient and all
   97 field points accepts at seven points: 7/97 for this fixed error. These
   domains have radically different worst-case guarantees.
2. **Omit the quotient:** ordinary evaluation of a negacyclic product fails
   even on an honest result away from those roots. Ring evaluation is not a
   homomorphism to an arbitrary coefficient-field point without the quotient.
3. **Publish and reuse verifier points:** after points 2 and 3 are disclosed,
   adding (X-2)(X-3) creates an exact wrong-output forgery for those checks.
   Reusable hidden points and a public commitment/opening protocol are
   different constructions. Neither is supplied by a bare equality function.
4. **Copy a bit constraint into a split NTT ring:** an explicit nonconstant
   idempotent satisfies e^2=e mod (X^8+1,97), but is not constant 0 or 1. Thus
   that ring equation alone cannot certify a scalar bit in this domain.
   A proof instantiated over a different/local ring can have different
   properties; this is an adaptation control, **not an attack on that paper**.

All eight scoped tests pass, including canonical witness bounds. The code has
no HE secret or untrusted-decryption API.

## Lifetime-matched state/body screen

The known nonzero error-polynomial degree bound is 2N-2. Counts choose the
smallest gamma with B*((2N-2)/Q)^gamma<=2^-128 for B=1024 attempts. The dense
field check is priced with the same algebraic lifetime target, using B/Q^r.
This is a **bound target**, not an assurance of the HE parameters, PRG,
reusable protocol or implementation.

Selected retained geometries:

| Profile | Point / dense rounds | Point index hint | Dense subring hint | Original reply | Extra quotient |
|---|---:|---:|---:|---:|---:|
| Mushroom selected Q32 | 9 / 5 | 2,304 B | 20,480 B | 131,072 B | 131,064 B |
| Semeion selected Q32 | 9 / 5 | 1,656 B | 29,440 B | 131,072 B | 131,064 B |
| Connect-4 raw Q32 | 7 / 5 | 112,896 B | 2,520 B | 262,144 B | 262,016 B |
| Connect-4 affine Q32 | 7 / 5 | 73,472 B | 1,640 B | 262,144 B | 262,016 B |

The small-layout verifier-index body decreases by about 8.9×/17.8×, while
Connect-4 grows about 44.8×. **All unbatched reply bodies nearly double.**
Secret points, per-answer hints, parsing/framing, generation and transport are
additional. These are counts for the existing masked public-polynomial stage:
its fresh encrypted answers/checking preparation remain. No new complete
query protocol or service advantage has been measured.

## Return to the plan

### Follow-up: post-output quotient batching

The next bounded subcomponent was executed separately: [batch oracle](../../experiments/bfv_search_lab/convolution_batch_certificate.py),
[tests](../../experiments/bfv_search_lab/test_convolution_batch_certificate.py),
[runner](../../benchmarks/convolution_batch_certificate_lab.py) and
[raw](../../benchmarks/results/publication-convolution-batch-certificate-screen-20260930.json)
at `2bd38f0`. The first unbatched raw is unchanged.

Fix all output coefficients before the client samples public random weights.
For each hidden point, the server supplies one weighted quotient. A nonzero
error-vector can average to zero with probability 1/Q; otherwise the polynomial
error degree is at most 2N-2. The modeled per-round bound therefore uses
(2N-1)/Q, with the same 1024-attempt/128-bit algebraic target. This is a
conditional calculation, not a reviewed adaptive receiver proof.

Six outputs/three factors/four checks agree with independent ordinary products.
Exhausting Q=17 weights and points gives 289 accepts in 4,913 checks for a fixed
wrong output, exactly the 1/Q cancellation term. Conversely, choosing weights
**before** freezing the outputs permits two compensating wrong outputs to pass
at every point. Four scoped batch tests exercise this order and witness bounds.

On both 16-reply Connect-4 count profiles, the quotient body becomes **57,316 B
instead of 262,016 B**, adding 896 B of public weights and one extra RTT.
The net payload saving within E70 is 203,804 B before compute/framing. An
optimistic payload-only RTT limit is 81.5 ms at 20 Mbps, 16.3 ms at 100 Mbps or
1.63 ms at 1 Gbps. These are **models**, not network measurements. On the
two-output Q32 profiles, batching instead increases the quotient from 131,064
to 589,788 B. Retain both positive and adverse counts.

**Do not promote either primitive as the system.** Batching improves the
many-output E70 variant; it still has larger wire cost than the original
direct-fresh gate, worse Connect-4 private hint state and the same owner
factory. No new end-to-end win or originality gate follows. The next
proof-aware screen must choose one of:

- Bind quotient/input polynomials with a real commitment and sound challenge
  order, then price openings/prover work against known ring proofs.
- Develop the now-screened batching receiver only if a complete-cost regime
  justifies its extra RTT/state; bind epoch/query/input and consume failures,
  with a full hidden-point transcript argument.
- Apply an independently justified private-point receiver to actual encrypted
  query arithmetic. Charge the much larger encrypted-query upload, hidden
  setup, every nonlinear stage and complete release semantics. Do not claim
  per-query factory removal from this primitive alone.

The closest [ring-native vFHE construction](https://eprint.iacr.org/2024/1764.pdf)
already expresses FHE arithmetic/non-ring stages with ring constraints and a
proof system. Polynomial certificates, sparse packing and proof-before-decrypt
are known ingredients. A paper contribution needs a new safe composition or
proof algorithm with a complete resource margin. The current screen supplies
neither a novelty proof nor a reviewed security reduction.

```bash
.venv/bin/python benchmarks/convolution_certificate_lab.py \
  --json-out /tmp/e70-certificate-new-run.json
```
