# E115: actual query framing and a classical ideal-XOF correctness card

2026-10-03. **Source-linked, conditional mathematical control.** No sampler,
parameter, HE implementation, native binary, release service or timing workload
was changed. This card does not prove that concrete SHAKE256 is a random oracle,
certify OS entropy, or prove protocol confidentiality. Its one illustrative
budget was frozen before exact calculation.

The [earlier marginal card](query-mask-marginal-correctness-card-20261003.md)
uses an explicit bounded-output PRG assumption and stops before exposing the
challenge seed. Here the alternative premise is a **public classical random
oracle with consistent infinite output**. This is the established model of
[Bellare and Rogaway, §1.1](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf), whose
paper explicitly separates model proofs from concrete hash instantiation. These
are alternative assumptions; their error terms should not be added together.
SHAKE256 is an XOF specified by [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
That fact supplies no application-specific random-oracle or entropy assurance.

## Actual source boundary

`owner_bgv.OwnerClient.encrypt` samples a single independent 32-byte seed after
validating and fixing the message. `_uniform_bulk` expands exactly

```
TAG || bytes.fromhex(key_id) || seed
```

where TAG is `cuhepy-lab-bgv-seeded-query-v1`, the checked key ID has 64 lowercase
hex characters, and the seed has exactly 32 bytes. Thus this fixed framing is
injective in (key_id, seed). `seeded_bgv._uniform` has the same candidate sequence.
Native owner encryption receives the mask already expanded by Python; it does
not replace this SHAKE sampling path. Its separately supplied entropy supplies
the two disjoint eta-bit CBD fields. This is a static source review, not a new
native execution or entropy/backend audit.

The bulk loop reads consecutive little-endian words, masks to Q.bit_length()
bits, rejects values at least Q, and pads unpacked trailing zero words to their
actual block length. For the frozen profile, each candidate uses eight bytes.
The [previous stream card](query-mask-stream-budget-card-20261003.md) proves
that the analytic M=N+6 cutoff has exactly the same candidate-prefix behavior
as this uncapped runtime. No cutoff was added to runtime code.

The source-selected E113 N16384/Q60 profile is still refused by the unchanged
general key-generation guard. A theorem about that source law and hypothetical
owner-only profile does not make the current general API support that profile.

## Fresh-input lemma and public seeds

Before query i, fix the complete previous transcript, owner setup, legal query,
graph, precision and context. Assume the next seed is an independent uniform
256-bit string. Let K_i count **all distinct already evaluated inputs** in the
same framing domain and key context, whether evaluated by an adversary, another
honest operation, setup enrollment, or an earlier query. An input counts even
if its output was not transmitted or only a prefix was read.

The probability the next input is already in this set is at most K_i/2^256.
On a fresh input, lazy sampling assigns an independent infinite uniform output
stream. This remains true given the whole prefix. Rejection sampling then gives
IID uniform residues, conditional on analytic nonexhaustion; fresh CBD coins
remain independent. No statistical uniformity of concrete seeded SHAKE outputs
is asserted.

After the query exposes its seed, the server can recompute this stream and
choose witnesses using everything it sees. That does not change the already
sampled sufficient correctness event **only if that event covers every admitted
server choice pointwise**. A bound for each fixed strategy is insufficient.
This card requires that implication and a complete relation verifier; it does
not construct one. Oracle queries after seed publication may reveal all mask
bytes, so this lemma alone supplies no privacy claim.

Let H bound all external classical oracle inputs over the declared lifetime,
A bound other honest/setup inputs, and T bound generated query invocations.
Conservatively K_i <= H+A+(i-1), including possible same-context seed reuse.
Adaptive contexts can only reduce this upper bound. The union loss is

```
epsilon_fresh <= [T*(H+A) + T*(T-1)/2] / 2^256.
```

This is a classical lazy-sampling argument. Quantum oracle access, seed grinding,
seed reuse, snapshot rollback, weak OS randomness, and unbounded epochs require
different premises or budgets. Count abandoned queries and all prior setup
calls; a public packet count alone does not determine H or A.

## One exact illustrative budget

The external freeze selects only N=16384, Q=1152921504606748673,
M=16390, T=2^32, H=2^64 and A=2^32. H and A are **declared illustrative
upper bounds**, not observed work, deployment settings or an attack-cost estimate.
The output budget is 131,120 bytes per queried input; it is not network traffic.

Exact Fraction and integer comparisons give

```
epsilon_fresh < 2^-159,
T*binom(16390,7)*(98303/2^60)^7 < 2^-186,
epsilon_fresh + epsilon_stream < 2^-158.
```

The leading term in epsilon_fresh is 2^-160. The looser displayed exponent
retains the other honest-input and collision terms. These bounds apply only to
freshness and uniform-stream exhaustion in the ideal model. They are not a
158-bit system-security claim. No ideal codec, nonzero-secret, false-admission,
authentication or private-side-channel term is silently assigned here.

## Composition obligation and return

If a separately reviewed setup event has failure epsilon_setup, every supported
fixed setup/prefix has a pointwise sufficient query event bounded by delta_i,
and false admission has lifetime probability epsilon_admit, then the
**unconditional marginal correctness** statement in this classical ideal-XOF
model is

```
Pr[any wrong admitted decode]
 <= epsilon_setup + epsilon_admit + epsilon_fresh
    + sum_i(delta_i + alpha_i).
```

Entropy and authentication failures must also be added if not already included
in setup/admission. The probability is not conditioned on the server returning
a response: a server can return only on rare bad masks. Feedback confidentiality,
actual proof soundness/attempt composition and private implementation assurance
are separate obligations. A reviewed all-witness consequence may replace the
earlier unit-conditioned delta_i; a merely honest-replay test may not.

This completes one known sampling/composition component of Q41. It is not an
original algorithm. The mathematical output-prefix card, primary source and
exact calculator are preserved under
`WORK/research-data/seeded-correctness-20261003/`; runtime remains unchanged.
Return to the secret-law and admission cards before any implementation or
parameter choice.
