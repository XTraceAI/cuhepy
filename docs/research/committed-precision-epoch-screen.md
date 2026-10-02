# E93/E94 return: source headroom, fresh-key order and conditional query noise

2026-10-02. Parent evidence `a6993d1`; branch
`experiment/committed-precision-epoch-20261002`. Preregistrations:
[E93A–C](committed-precision-preregistration-20261002.md),
[E93D refinement](committed-precision-refinement-preregistration-20261002.md),
[E94](adaptive-query-phase-preregistration-20261002.md).
The [lemmas](committed-precision-lemmas-20261002.md) and
[closest comparison](committed-precision-closest-work-20261002.md) separate
arithmetic assurance from the unimplemented full protocol/security premises.

## A. The original source budgets were empty for a reason

The owner encryption phase is `m+t*e`, with centered-binomial support eta and
centered message cap floor(t/2). Ordinary public-key BGV has additional key,
ephemeral and secret products, and has a different fresh bound. For h products,
the owner all-support phase envelope expands into

`N*h*M^2 + 2*N*h*M*t*eta + N*h*t^2*eta^2 = N*h*(M+t*eta)^2`.

All eight E72 modeled moduli are reproduced independently from the E68 input
profiles. They sit just above twice this centered phase bound. None has ideal
quarter-LUT source margin; all have ordinary nearest-message half margin.
The error-product term is about **95.4%** of the all-support bound. Exhausting
6,561 N2 message/error cases checks 13,122 phase coefficients and attains
the support bound. Centered plaintext carries are explicitly separated from
noise, rather than labeling the full phase as Gaussian error.

The 32 source-context cards include original Q and new NTT primes above
4P/6P/8P with every term recomputed. The 24 changed cards have positive ideal
quarter margin, although the prime just above 4P often leaves too little room
for switching. Same sampler support makes these correctness-valid contexts;
their security is unapproved and they need new keys/index. The full-domain
FDFB-Compress control has two bootstraps and a real half-margin theorem for
its stated even-p context, not a free implemented odd-t workaround.

Raw [initial source audit](../../benchmarks/results/publication-source-phase-budget-screen-20261002.json)
and [repeat](../../benchmarks/results/publication-source-phase-budget-screen-20261002-02.json).

## B. Precommit before target coins, not posterior independence

The exact scalar toy exhausts **455,625** support branches with **1,440,000**
weighted sampler coin outcomes and **1,822,500** mixed/rounded phase identities.
Four sign/stage views share target/masks/errors. The switched mask and fresh
target are unconditionally independent. A full key transcript has posterior
ternary masses `(2,4,2)`, so conditioning on key bodies does not preserve the
IID uniform law. This q5/t3 toy is not a secure/decryptable search instance.

The registered MGF combines target rounding and honest CBD key errors, with
shared weights aggregated before squares. Body rounding and original S^2
residuals are deterministic terms. Whole-family failure covers any later
subset; a new source query after the target key is visible is outside that
ordering argument.

An explicit revealing-toy negative at dimension 32/kappa 8 gives:

| Event | Exact tail |
|---|---:|
| Fixed all-plus weights, bound24 | `9008230/617673396283947` (about 1.46e-8) |
| Weights chosen as sign(T) after revealing T | `23744726695936/205891132094649` (about 11.53%) |
| Claimed single-event target | 1/256 (about 0.39%) |
| Correct complete 2^32 sign family, bound52 | 0, since the sum is at most32 |

This falsifies an omitted ordering premise; it is not an attack on RLWE or a
published scheme. A fresh valid homemade BGV fixture uses actual CBD_eta1
switching errors, checks eight decoded coefficients and sixteen view budgets.
Fifty-two public certificate corruptions reject before the opaque callback.
Full recomputation repeats server work and does not authenticate upstream
scores, key generation, PBS, IDs or private decryption.

Raw [initial epoch screen](../../benchmarks/results/publication-committed-precision-epoch-screen-20261002.json)
and [repeat](../../benchmarks/results/publication-committed-precision-epoch-screen-20261002-02.json).

## C/D. Cost frontiers belong to the strongest known control too

The initial 2,560 paid cards use eta 21, prefix512, sparse/dense coefficient
sets, lifetimes1/8/32/256/4096, both key families, omission0/1 and four degrees.
They include key generation and bodies, one source square shared across epochs,
fresh provisioning RTT, query/index/cache bodies and duplicated verifier work.
PBS auxiliary keys, proof, private native work/RSS, durability and security
remain unknown costs. The strong standard precommitted shared epoch has
identical arithmetic and key resources.

The coarse initial grid has 120 passing statistical and 120 deterministic
cards. E93D retains it and independently reproduces every bound/budget before
checking **6,400** points across 640 tuples and every power-of-two degree
2^11–2^20. In **134** tuples the statistical control has a smaller first
passing degree: 60 change from 524,288 to 262,144, while 74 pass at 1,048,576
and the deterministic control has no passing degree within the declared grid.
None of these cards certifies a degree 2048/8192 encrypted PBS. These are
conditional sufficient bounds, not actual failures or measured speedups.

Raw [refinement](../../benchmarks/results/publication-committed-precision-frontier-screen-20261002.json)
and [repeat](../../benchmarks/results/publication-committed-precision-frontier-screen-20261002-02.json).
**R6:** keep the restricted proof/controls; stop generic fresh-epoch composition
as a main original mechanism, then execute Q20/E94 rather than inflate Q blindly.

## E94. Condition on the index; average only fresh query errors

For any fixed supported index phases I_j and any adaptive centered query
messages u_j, the phase is `sum I_j*u_j + t*sum I_j*E_j`. The first term is
bounded by N*h*F*M. Condition on the complete prior history/index/messages,
then use the exact CBD MGF for the independently generated query errors.
This gives a conditional-history lifetime guarantee without pretending the
reused index or product noise is independent Gaussian noise.

Checks include 6,561 fixed-index/message/error cases, 11,664 weighted CBD
coin outcomes and 13,122 phase coefficients. A dimension 16 fixed-index tail
is exactly `33/2147483648` at bound174, making the test nontrivial. If the
index is instead chosen after seeing the fresh errors in a revealing toy,
failure rises to about **97.55%** against a 1/256 target. Repeated query
errors require aggregated weights, not an IID sum. These are premise
falsifiers, not cryptanalytic attacks.

A fresh homemade **seeded owner** BGV fixture (N8/t17/eta 21) chooses query
messages using the fixed private index phases before independently sampling
query errors, then matches all eight integer/ciphertext phase coefficients.
The public policy has a recomputed exact budget and volatile one-use freshness
ledger; tests cover exhaustion, abandoned generation, replay, wrong bindings
and concurrent reservation. It supplies neither durable state nor proof of
sampling, original scores or side-channel safety.

All **40** eight-geometry/lifetime cards regain positive source quarter margin
at the **same modeled depth-one Q**. The previous all-support bound is
**33.72–37.49×** larger than the new source bound; this is not a runtime ratio.
Conditional minimal-correctness Q could lose 5–6 bits, but that route would
need new keys/index and parameter review. The original linear production
circuit and its Q are a different control, not silently replaced by this model.

Example at lifetime 4096, Connect4 global-affine: P decreases from
2,890,884,059,136 to 85,731,802,691 while modeled Q remains 5,781,768,241,153.
The complete conservative target degree still starts at 131,072 in the tested
grid. Better source margin is useful; it does not create a small-ring PBS.

Failure allocation is explicit: source kappa 129 plus one target epoch
kappa 129 gives arithmetic failure at most2^-128. Adaptive fresh-target
epochs need kappa 129+ceil_log2(lifetime) each. Their lifetime threshold equals
the one committed-batch threshold, but their paid keygen/upload/RTT costs
do not. This source lemma does not make old target keys statistically independent
of adaptively chosen switch inputs. Proof/PBS/privacy/private failures are
uninstantiated, rather than included as zero.

Raw [E94 initial](../../benchmarks/results/publication-adaptive-query-phase-screen-20261002.json)
and [repeat](../../benchmarks/results/publication-adaptive-query-phase-screen-20261002-02.json).
**R6:** keep this useful known conditional source interface. Next is
[Q21/E95 late owner rerandomization](late-owner-rerandomization-plan-20261002.md),
with a true-uniform mask first, exact all-target-key law, shared-output controls,
original-input/provenance binding and every owner/traffic/proof cost charged.
No original complete main construction or Q6–Q10 gate is selected.

## Reproducibility and preservation

The four initial/repeat pairs retain parent HEAD plus explicit working-source
hashes; the parent alone is not a snapshot containing the added code.
All **309 scoped tests** pass across fourteen specified CPU files, including
82 added here; explicit Ruff checks cover ten new Python files. This is not
whole-repository CI, runtime/parameter assurance or a security proof. The
[validation receipt](committed-precision-execution-validation-20261002.json)
and [manifest](publication-committed-precision-execution-manifest-20261002.json)
pin raw/source/literature/test dependencies. Production sources, old scopes,
main/staging, frozen measurements and all earlier checkpoints remain intact.
