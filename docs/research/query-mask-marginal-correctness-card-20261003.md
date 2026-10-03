# Q41/E115 partial component: marginal query-mask correctness

Status: **conditional mathematical review only**. This is an ordinary sufficient-event,
PRG and stopped-prefix argument, not an original theorem, implemented release gate,
SHAKE security approval, complete protocol review or parameter certificate. No
experiment, benchmark, build, new sampler or security test was run for this card.

This corrects the earlier blanket public-seed warning. Revealing the seed prevents
replacing the **joint seed/output transcript** with an independent uniform output
through an ordinary PRG hybrid. It does not prevent a reduction for a marginal,
seed-blind correctness event, provided that event pointwise dominates failure for
every subsequent server choice. Correctness and protocol confidentiality require
separate arguments.

## 1. Actual source and proposed event

The reviewed owner path samples one fresh 32-byte `secrets.token_bytes` seed, expands
`SHAKE256(TAG || key_id || seed)`, then samples separate CBD entropy. The seed crosses
the wire. Its rejection loop neither filters owner seeds nor currently imposes a
finite stream budget. These statements describe the inspected Python sources, not
an audit of OS entropy, native equivalence, concurrency or deployed call sites:

- `experiments/bfv_search_lab/owner_bgv.py:34`: `_uniform_bulk`.
- `experiments/bfv_search_lab/owner_bgv.py:162`: owner encryption, including the
  separate native entropy argument and separate Python CBD sampler.
- `experiments/bfv_search_lab/seeded_bgv.py:25`: scalar expansion of the same stream.
- `experiments/bfv_search_lab/compressed_query_bgv.py:40`: deterministic codec
  dimensions; `:141` compresses without changing the seed or adding randomness.
- `experiments/bfv_search_lab/finite_lifetime_noise.py:61`: ordinary fixed-phase
  coefficient weights; `:94` supplies the uniform maintenance-error envelope.

Before query i, let H_i be the entire honestly generated prior transcript, including
earlier public seeds and adversary activity. Let Z_i contain the current owner
secret, enrolled index, reused evaluation-key errors, graph, epoch and parameters.
Fix the message, precision, context and all phase weights before drawing the next
seed. New seeds and CBD entropy are modeled as independent uniform source coins;
this is an explicit modeling premise, not an entropy-assurance result.

Let B_i(H_i,Z_i,A,E) be an efficiently computable Boolean sufficient bad-margin
predicate. It must not require the target seed. An intended form computes the
original c0 from A, the actual codec error Delta(c0), and exact integer affine
product/trace contributions. For a fixed setup and message, each coefficient has
the form

```
v_k(Z_i,message) + sum_j w_kj(Z_i) * (t*E_j + Delta(c0)_j).
```

Add a pointwise envelope U_i for ALL accepted common-integer digit witnesses and
server choices, then check raw no-wrap and the full terminal/private-centering
margin, including terminal rounding and every live output position. Weights can
be dense and private in this proof calculation. Polynomial-time computability is
enough for the reduction; this asserts neither cheap online computation nor a
scalable certificate implementation. Exact integer/rational comparisons avoid an
unjustified numerical optimizer or an intractable existential search over witnesses.

The required implication is pointwise, not an average over server strategies:

```
Good(H_i,Z_i) and B_i(H_i,Z_i,A,E) == false
  => every response admitted for that query decodes to the exact intended result.
```

This implication is an outstanding protocol/phase obligation. This card does not
establish that a present verifier enforces the required relation. False admission
and authentication failure require their own bounds.

## 2. Finite stream reduction and exact bound

Write b = bit_length(Q), w = ceil(b/8), p = Q/2**b. Take M_i candidate words and
L_i = 8*w*M_i output bits. A truncated sampler processes these same successive
w-byte words, masks their high bits exactly as `_uniform_bulk` does, and stops at
N accepted values below Q. Mark exhaustion as bad. This is an analytic truncation
in the proof, not a patch to the uncapped source.

For truly uniform L_i bits, the probability of exhaustion is exactly

```
alpha_i = Pr[Binomial(M_i,p) < N].
```

Conditional on nonexhaustion, the N accepted values are independent uniform
residues below Q: acceptance indicators are independent of accepted values. The
bulk block reads and trailing-zero padding of `gmpy2.unpack` preserve this word
sequence. M_i and the bit budget must be chosen before the challenge and large
enough for a declared lifetime abort budget; p > 1/2 does not by itself approve a
particular budget. Any special-case changes to masking/reading need a new review.

Assume bounded-output pseudorandomness for the exact context-prefixed family

```
G_context(S) = first L_i bits of SHAKE256(TAG || key_id || S), S uniform in {0,1}**256.
```

The assumption must cover the declared output lengths, allowed adaptively chosen
preexisting contexts, auxiliary prefix state and total distinguishing work. This
card supplies no proof or concrete security level for SHAKE under that assumption.
It is not a claim that the output is statistically uniform or that SHAKE bytes
remain unpredictable after S is published.

Define D_i to generate the complete REAL prefix through query i-1, retaining the
owner state and any adversary state. At the next query it receives only challenge
bytes, performs the truncated sampler, samples independent CBD E, and outputs 1
iff Good holds and either truncation exhausts or B_i holds. It then stops. It never
needs to send the unknown challenge seed or simulate a target-query response.

Suppose the ideal-uniform-mask bad-event bound is delta_i, uniformly over every
eligible good prefix/setup. Let Adv_i be the distinguishing advantage of this
specific efficient D_i. Since exhaustion is included in the single event,

```
Pr_real[Good_i and sufficient bad event at query i]
  <= delta_i + alpha_i + Adv_i.

Pr_real[any admitted decoding failure during at most T queries]
  <= epsilon_setup + sum_{i=1}^T (delta_i + alpha_i + Adv_i).
```

Here epsilon_setup bounds the probability that any required setup/epoch event is
bad. Context-dependent budgets can use their expectation under the real prefix,
or declared uniform upper bounds; no uniform conditional PRG claim for every
possible prefix is necessary. A randomly selected stopped prefix gives a standard
T-times-advantage formulation when the same family/budget supports that reduction.
The per-query comparison uses a real prefix followed by one ideal mask. It does
not require or construct an ideal full transcript with a consistent public seed.

The unbounded real sampler agrees with the truncated sampler until exhaustion.
All real behavior beyond the budget is conservatively charged to that event. One
PRG comparison controls bad margin OR exhaustion; two separate advantages are not
necessary. If OS entropy is instead modeled computationally, its applicable
simulation/distinguishing budget must be added, not silently treated as zero.

## 3. Unit-key and exact codec-law conditions

The potential exact codec-law component needs an additional statement. If the
fixed secret is a unit in R_Q and A is uniform in R_Q, multiplication by s is a
bijection. Thus c0 = message + t*E - A*s mod Q is uniform in R_Q and independent
of E, even for a fixed owner message and fixed setup. Delta(c0) has the exact finite
codec PMF, including the final Q tail and any bias; its coordinates are independent
of E and each other. This observation is standard.

It does NOT imply independence of subsequent switch digits and errors. Reused-key
maintenance must remain bounded uniformly over all accepted witnesses, as in E102,
unless a separate dependency theorem is proved. Correlated output coefficients
also do not become independent just because individual inputs have a finite PMF.

For the actual ternary secret sampler, unit probability has not been certified.
Charge the probability of any nonunit key to epsilon_setup, derive a law for
nonunits, or use a theorem that does not need invertibility. Do not presume all
honest keys are units, silently condition the sampler, or introduce secret-dependent
setup/response rejection. For adaptive re-enrollment, every new epoch and updated
setup must have an appropriate conditional setup bound; earlier seeds may be
public, but the next challenge must still be fresh and independent of that state.

## 4. What breaks the stopped-prefix argument

- The message, index, keys, graph, precision or phase weights are chosen or changed
  after seeing the target seed/mask, while the uniform-mask theorem only covers
  fixed choices. Alternatively they must be covered pointwise in the bad predicate.
- The owner retries or grinds seeds using a seed-dependent rule. `_uniform_bulk`'s
  internal residue rejection is not owner-seed grinding, but caller behavior could
  be. A fresh single independent seed law cannot be applied to a selected seed.
- The bad predicate needs the target seed, its hash, a target transcript response,
  the server's seed-dependent eligibility choice, or an unbounded computation.
- Failure is bounded for each fixed digit strategy on average instead of by one
  pointwise envelope for every accepted strategy. For example, a uniform A from
  K values can make each fixed choice j fail only when A=j (probability 1/K),
  while a server choosing j=A fails always. A valid sufficient event would charge
  the union of those choices and would not claim the smaller probability.
- The claim concerns failure probability conditioned on receiving/accepting a
  selected response. A server can respond only on rare bad masks. The lifetime
  bound is unconditional; it is not a conditional correctness guarantee for that
  selected subset. Attempt/replay multiplicity also needs an explicit lifetime.
- Setup updates, owner callbacks or future rounds after the challenge are needed
  to decide B_i. Stopping avoids the missing seed only for a present sufficient
  event; it does not prove security of future transcripts or private feedback.

Ordinary repeats/collisions among independently drawn seeds can be included in the
PRG distinguishing budget. If a separate collision term is stated, avoid counting
it twice and specify its fresh-seed/epoch domain. An entropy pool or explicit seed
reuse is a different experiment.

## 5. Research gate and scope

This card clears one logical obstruction to a **marginal correctness-only** pilot.
It proves neither the seed-based HE confidentiality assumption nor immunity to
accept/reject leakage, key-dependent messages, selective failure, implementation
side channels or malicious-context enrollment. Production parameter approval is
also outstanding.

First grant ideal masks and unit keys, use the strongest equally informed generic
conditional bound, and ask whether the actual E113 N16384/d512/radix15/Q/P profile
can pass complete raw AND terminal margins at drop23 instead of drop22. Stop if
the frontier is unchanged or the candidate merely restates the generic control.
Only then pursue actual-sampler/unit-key/lifetime obligations. Q41/E115 remains
PARTIAL with no originality claim.

Relevant prior controls are [E102](finite-lifetime-noise-screen.md),
[E111](decoder-event-screen.md), and [E113](one-prime-screen.md). The already retained
[BGV dependency analysis,2504.18597v3](https://arxiv.org/html/2504.18597v3) and
[average-case critique,2025/1036](https://eprint.iacr.org/2025/1036) remain mandatory
noise-analysis comparisons. This card adds no new literature acquisition.
