# Frozen Q46/E120 first-component authorization

The root froze the following prospective specification on 2026-10-03, before any new code, test or selected-profile calculation. Its draft-stage stop language describes that earlier drafting state; this header authorizes only the listed bounded first component. Draft SHA256: `faf51eecbf259ef98e87eebe69e740dc47b035481798b3be7c47e7471d61c133`. Static reviews are preserved in the new external archive. Implementation ownership is limited to the three new paths recorded in the freeze receipt and one new raw/card. No later MGF or private operation is authorized by a favorable result.

---

# Proposed Q46/E120 first component: one owner precision-selection screen

2026-10-03. **Scope draft only. Do not execute until root freezes this
specification and gives GO.** At drafting time there has been no selector
import/execution, new code/test, public parameter arithmetic, probability
calculation, secret/key/ciphertext operation, native build, estimator, GPU,
proof backend, timing or service work. Reads and SHA256/source identity
inventory are provenance, not a new parameter result.

Evidence parent: `dbd7e204657f2b142b5fbde6593a5d40badda774`, branch
`experiment/multilimb-consequence-screen-20261003`. Repository:
`/home/pete/yavor-projects/xtrace-work/cuhepy-bfv-research`. Root owns governance,
branch, repository additions and checkpoints. This proposal is outside Git.

## 1. Exactly one hypothetical owner graph

Fix N16384, dimension d512, count8192, padded D512, t1031, CBD eta21,
requested Q120 with `rns_modulus=True`, gadget radix bits30, and the existing
25-bit terminal selector. No profile, prime, radix, terminal, precision-success
or workload grid is permitted.

The source-selected prime tuple is exactly
`scheme._rns_coefficient_primes(16384,120)` **in source auxiliary-base order**.
Its product must equal the historical
`q_hex=ffffffffffc00020000003bffc0001`. Recover P by the exact source
`compact_bgv.terminal_modulus(Q,1031,25)` rule. Stop on source/product/format
drift; do not replace the historical value or search another profile. Selected
integers are NOT computed in this proposal.

The historical `benchmarks/results/bgv_owner_pipeline_8192.json` has source
`11c41253c8d5ee61ac35c229fabbdeeabe5e5a54`, q_bits120, radix30 and terminal25.
Its unrounded exchange348354 B and response102488 B are historical
topology/format anchors, not a matched deterministic owner-compression
frontier, a current measurement or security approval.

**Prospective owner enrollment is different from that captured index.**
`benchmarks/bgv_owner_pipeline.py` calls `case.encrypt(tile)`;
`coefficient_search_lab.Case.encrypt` calls public BGV encryption. Its index
phase law does not establish W=1+t*eta. This component assumes a NEW properly
encoded owner-encrypted index with phase M_i+t*e_i, |M_i|<=1, |e_i|<=eta.
The owner query has signed d-position message and fresh error |E_l|<=eta.
Both candidate and controls receive this same narrower owner law and pay
future reenrollment separately. No existing ciphertext is relabeled, no
owner index is created, and Q42's typed owner-only contract remains absent.

## 2. Known complete envelopes and admission distinctions

Retain the E15 joint-support identity: each final coefficient is D times ONE
shifted tile-product coefficient, or zero, not a sum of every tile. Include
the actual partial group, all output positions, product relinearization and
every remaining joint-butterfly maintenance level. The complete integer-lift
bound must be congruent to the actual graph phase modulo Q. No intermediate
no-wrap requirement is substituted for complete final/terminal centering.

Let L=ceil(bit_length(Q)/30), B=2^30, W=1+t*eta. The **main broad E115
all-choice admission law** permits each common global digit in[0,B), with
recomposition congruent to the cut source modulo Q, including total words>=Q.
Its switch envelope is fixed unchanged:

```
S_broad = t*eta*N*L*(B-1).
```

Give the stronger ordinary **canonical-admission-only comparator** the
existing E113 exact maximum digit-sum control. Let M(Q,30) be the maximum
base-B digit sum over 0<=x<Q, derived by the registered first-differing-digit
formula from `one_prime_bounds.maximum_digit_sum`. Then

```
S_canonical = t*eta*N*M(Q,30).
```

This latter cap is valid only when each shared tensor is the digits of ONE
canonical common word<Q. It must not silently tighten the broad all-choice
law. Record the two admission contracts and unknown complete verifier costs.
Each matched generic evaluator receives ALL the same support identities,
canonical optimization, public selectors, integer inversion and byte rules.

For either registered S and codec drop b, set

```
J_0=0,
K_b=floor((2^b-1)/t), J_b=ceil(K_b/2) for 1<=b<bit_length(Q),
max|E+delta/t| = eta+J_b,
F_S(b) = D*(d*W + N*t*W*(eta+J_b)) + (2D-1)*S,
C = ceil((N+1)*t/2),
B_safe = min(floor((Q-1)/2),
             floor(Q*(floor((P-1)/2)-C)/P)).
```

The exact strict source terminal conditions are
`2*F_S(b)<Q` and `2*(ceil(P*F_S(b)/Q)+C)<P`. For odd Q,P these are equivalent
to the integer boundary `F_S(b)<=B_safe`. Stop if terminal/primitive split/
gcd/t/dimension prerequisites fail. This is an upper bound under a registered
complete envelope, not a proof that no sharper deterministic argument exists.
Do not call it a globally optimal full-support boundary.

Derive each largest admitted drop by INTEGER INVERSION, not a drop sweep.
Writing A=D*N*t*W and F_S(0)=D*(d*W+N*t*W*eta)+(2D-1)*S, let
H_S=floor((B_safe-F_S(0))/A). If F_S(0)>B_safe, record that envelope's
unrounded rejection. Otherwise `J_b<=H_S` is exactly

```
2^b <= t*(2*H_S+1).
```

Therefore the largest positive allowed b is the lesser of
`bit_length(Q)-1` and `floor_log2(t*(2*H_S+1))`, with the zero-drop source
format separately admitted when F_S(0)<=B_safe. Verify the resulting boundary
and, if in range, its immediate successor using the original strict
inequalities. J_b is nondecreasing because its integer floor/ceiling arguments
are nondecreasing. Report `b_det_broad` and `b_det_canonical`, with exact
maximality **within the respective registered envelopes**. No other precision
outcome is sought.

The current general keygen, rounded-query and support/terminal metadata guards
are evaluated ONLY as public arithmetic expressions. Record any discrepancy
with this prospective owner certificate. Never instantiate keys, ciphertexts,
private caches or internal objects to bypass them; never claim actual API
support from a mathematical boundary.

## 3. Exact byte schema and one deterministic candidate rule

Use the actual existing rounded-query and compact-v1 response fields, with
fixed dummy shape lengths only. No ciphertext/seed/body values are generated.
Let `bin(l)=l+(2 if l<256 else 3 if l<65536 else 5)` and `arr(c)` be1/3/5
for c<16/c<65536/otherwise. Use standard source-msgpack positive integer and
UTF8 string sizes, including every header and framing transition. No response
precision, output count, ID policy or component is removed.

For b>=1, the exact source word maximum and coefficient width are

```
h,r = divmod(Q-1,2^b),
max_word_b = h*t + min(t-1,r),
w_b = bit_length(max_word_b),
qbody_b = ceil(N*w_b/8).
```

The rounded query is
`[binary_rounded_tag, binary_key_id32, binary_seed32, positive_integer_b, binary_body]`.
Its size is

```
Qbytes(b)=arr(5)+bin(len(rounded_tag))+bin(32)+bin(32)
           +uint_size(b)+bin(qbody_b).
```

For b=0 use the ACTUAL four-field seeded tag and N*bit_length(Q) body;
do not substitute the five-field rounded header. All b in this one selected
profile are below128, so the drop field is a one-byte positive fixint.

For the unchanged response, let G=ceil(count/N), pbits=bit_length(P),
rpoly=ceil(N*pbits/8). The source compact-v1 header is
`[UTF8_compact_tag,N,t,binary_P_ceil(pbits/8),binary_key_id32,count,d]`.
The complete response is `[header, [[binary_c0,binary_c1], ... G pairs]]`:

```
Rbytes=arr(2)+header_size+arr(G)+G*(arr(2)+2*bin(rpoly)).
```

Derive header_size from the exact pinned schema, not historical subtraction.
Compare the resulting response format count with the historical anchor as
a FORMAT control only; any mismatch stops rather than selecting another tag.
Packets/counts here exclude unknown authenticated envelopes, proofs/receipts,
enrollment, transport headers, updates and retired epochs. Those are not zero.

Prove monotonic format selection without a precision grid. For any fixed
canonical c, writing c=2^b*(2a+e)+r, e in{0,1}, the source word at b+1 is
`t*a+((e*2^b+r) mod t)`. If e=0 it is at most the old word
`t*(2a)+(r mod t)`; if e=1 its residue is at most t-1 while the old word is
`t*(2a+1)+(r mod t)`. Thus every word, the maximum word, w_b, qbody_b and
their bin framing size are nonincreasing across positive b. The constant
positive-fixint drop header preserves this monotonicity.

Choose the SINGLE `b_candidate` as the least allowed drop strictly larger
than `b_det_canonical` for which

```
100*(Qbytes(b_candidate)+Rbytes)
    <= 95*(Qbytes(b_det_canonical)+Rbytes).
```

The smaller canonical-comparator exchange is the conservative denominator,
even if it differs from the broad-law baseline. The candidate still uses
S_broad and the broad all-choice law. Admission contracts differ, and complete
verification costs are unknown, so this is a stringent NECESSARY usefulness
screen, not a complete same-contract advantage theorem. Report the broad
baseline exchange separately. Use monotone integer binary search (at most
ceil(log2(bit_length(Q)))+2 format probes), then check predecessor/boundary;
do not enumerate drops, fit another target, or use the old unrounded348354 B
as the denominator. Stop if either required baseline is unadmitted, no drop
meets5%, or a justified least-boundary source rule cannot be established.

## 4. Candidate suffix-only falsifier; no statistical certificate

Only AFTER freezing the resulting one candidate scalar and byte counts,
derive the public norm caps K_i using exact adjacent-power comparisons
`q_i^K_i<=N^(N/2)<q_i^(K_i+1)`, clipped at N, and common K=max_i K_i.
Retain original source prime order; a separately sorted pure certificate
representation must not reorder native/key limbs. The E119 weighted divisor
is `product_i q_i^k_i`, NEVER Q^max(k_i). No secret/rank/root sample is read.
The guaranteed prefix has m=N-K; its fixed positions are the original first
m coefficients, not retrospectively selected small-weight positions.

Define the broad candidate integer event threshold and paid suffix

```
h = floor((B_safe-(2D-1)*S_broad)/D)-d*W+1,
suffix = K*t*W*(eta+J_b_candidate),
h_retained = h-suffix.
```

If h_retained<=0, the suffix alone consumes this complete worst-case terminal
margin: record the exact conservative-envelope stop and return to R6. This
does not prove that every possible argument/system fails. If h_retained>0,
record only a NECESSARY feasibility check; stop and return for a separately
registered efficient MGF/probability component. No MGF, Chernoff/Hoeffding,
Gaussian probability, all-zero numerical mass, ideal-XOF/ROM/exhaustion or
lifetime certificate is evaluated here. No favorable result permits adapting
the candidate, source, numerical method or resource budget.

## 5. Prospective public implementation, caps and evidence

After GO, a small external exact-integer calculator may reproduce public
selectors, compare their product with the old q_hex, derive P, boundaries,
format counts and the one suffix card. Importing/executing company selectors
or any new source/tests is forbidden BEFORE that GO. A literal independent
selector reproduction must use the same candidate order/primality decisions,
then independently validate selected unsigned64 primes and splitting. Do not
substitute a new prime algorithm's first result without matching source.

Cap the one arithmetic process at60 seconds/256 MiB. Cap each source prime or
terminal selector at4096 candidate checks; stop unknown on resource/selection
failure. No Q/PMF/support enumeration, giant power MGF, secret sampling, key
setup, lattice estimator, native build/CUDA, proof callback, backend, service,
packet encryption/decryption, download or timing measurement is allowed.
Public power/norm integers and format-size arithmetic are bounded and exact.
Stop rather than broaden any cap or add another profile/candidate.

Preserve the proposed/frozen specification, current source/hash inventory,
public selector identities, source/argv freeze before the one calculation,
stdout/stderr/exit, failures and fixes, selected JSON and final receipt under
`WORK/research-data/multilimb-consequence-20261003/`. Small public arithmetic
checks may cover inversion's exact boundaries, monotone word/framing rules,
the two admission-law caps, conditional suffix accounting and numeric aliases;
do not repeat any registered main graph as a grid in tests. Root will assign
any implementation/test path ownership after scope freeze. No repository path
is edited by this draft or by an unassigned follow-up.

All conclusions remain a hypothetical owner-reenrollment/count/support card.
They provide no actual sampler, seeded-law, parameter, cryptographic assurance,
novelty, publication, measured performance or complete-system approval.
Plaintext client caching is permitted and remains a required future control.

## 6. Pinned source/evidence inventory at proposal time

Repository-relative SHA256 values (metadata inventory only):

```text
9c964854dcb24b38b63788c87d261ad178c1e885a6a6af1a1b623569be6d0fa8 docs/research/multilimb-owner-consequence-plan-20261003.md
7bba9ddd6d43ada1a4db6af817ac78e9377c248f84118c1327b053e11a727be4 src/cuhepy/bfv/scheme.py
b6adf11b6edb56f71868bc9315aa0a496f74e14d6b8665034fe6a7ab787ef85e src/cuhepy/types.py
ea5e8fd75147d02683513a70af2fe3b68693bd8046c80489adea0a2a2df755be experiments/bfv_search_lab/shallow_bgv.py
d8ab7f0cc208ce2ba844dddd7ad3e21acf234341326834b1241be6dc756d5c10 experiments/bfv_search_lab/owner_bgv.py
7e8631304dde122c4755f5f7391ef8ba6b9be213fd2c667a473b388175890272 experiments/bfv_search_lab/seeded_bgv.py
51f7829b384c41d344aae2410501cd86bf3c190ac211aed4e529915daf46fde5 experiments/bfv_search_lab/trace_bgv.py
07a1312356851b670dfc51da9bd648aee6aad22250b48d7a13575903ae388167 experiments/bfv_search_lab/butterfly_bgv.py
d74b6a3c7650a33cdbdaffdc7570e684ddcb15d9c7bab56698b937a72b151ae3 experiments/bfv_search_lab/support_bounds_bgv.py
cc5639f4ceb2e60419d748d3e29e97c05b2202bc6ba28241b4f01281cc2b5836 experiments/bfv_search_lab/compressed_query_bgv.py
4b98630622c75052a74ae4f1380bc529f2db088ad961716147b858f3936e0ff9 experiments/bfv_search_lab/compact_bgv.py
f5bfdc142edca9fbbfaf7b8eeb987e883704611be726957d955b1eaf88387f93 experiments/bfv_search_lab/one_prime_bounds.py
534df8e111c6a9b66ce50ec7bb3821d9aed0eea1eef60cbfac1b7b1b81a3caa0 experiments/bfv_search_lab/squarefree_projection.py
56d1ba8295b51e36d298b86056137d9814d70335787b956e73700a162324034a experiments/bfv_search_lab/results_bgv.py
6e31742ada14844715f1f04b9f02db3cfe0d7ed88615254e0cf4b73805902330 experiments/bfv_search_lab/transport_bgv.py
2d9c250b3b7d00fbe63dd758280b3c8b92a9ca5c858afd0c81493ebed1c9cdee benchmarks/bgv_owner_pipeline.py
c8bce962079e9f7411bec4d7a93241e4392f6762afa976a6868d3dd4daf6e373 benchmarks/coefficient_search_lab.py
8ffb5f9e92a807bda01c1bb10e41b377df65a166839e9dfc0e53fb1faf27b8b6 benchmarks/results/bgv_owner_pipeline_8192.json
0ada0a43abd7b9166234efa076881414e07ae0d21617e3a27982702cc9493900 docs/research/seed-blind-admission-card-20261003.md
21e1f4735ea13da8c8a023614c73977ca77afd7d693fa6459da6cecd068af4db docs/research/nonunit-projection-screen-20261003.md
5a8de3b3878cbe7c207c863c665e754e590756febe9382c919b64970a1e8547e benchmarks/results/publication-nonunit-projection-20261003.json
e254ce32e5ddf283134abd5b47f4e10f9f4bb1468a14133025cd8676548c090b docs/research/squarefree-projection-screen-20261003.md
214706d4077dd142dec24c2933910284389a8cfdcd6a59888d1873869320c4d3 benchmarks/results/publication-squarefree-projection-20261003.json
```

These identities must be rechecked after root freezes the proposal and before
any calculation. A source update requires a disclosed new specification,
never silent substitution. No result/drop/P/prime/prefix/suffix value has been
calculated for this proposed Q120 owner consequence in this document.
