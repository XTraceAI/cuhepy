# E74: structure-aware programmed-mask discriminator

2026-10-01, before new oracle/count execution. R3's literal E72/E73 variants
failed the useful/original mechanism gate; return to the plan's bounded R4
alternative. Do not replace production masks or the full-field verification
gate. This is a test of one concrete proposal, not all PCGs/correlations.

Proposed known code/noise ingredient: a public n-by-k field matrix A, a fresh
private s and private fixed-weight nonzero noise e give r=A s+e. An owner with
private M precomputes P=M A, then computes M r=P s+M e. A fresh independent HE
encryption of each answer is still required. No public answer bank/related
encryption coins or undeclared helper. Fixed-weight noise is a distinct
assumption from Bernoulli LPN in the cited trapdoored-matrix construction;
this screen must not claim parameter assurance from that paper.

First price the actual factory: each retained row touches at most F feature
coordinates, even if the full query has n coordinates. A uniform A generally
densifies P, costing k products per row; sparse e contributes expected F*tau/n
when its tau positions are uniform/private. Compare k+F*tau/n with F, plus
A s generation, P construction/storage, sparse gathers and fresh encryption.
Use the largest row width as an optimistic upper bound if the exact average
is unavailable. Do not compare against an artificial dense m-by-n matrix.

Required algebra: independently check P s+M e=M(A s+e), through real CRT
coordinate schedules including sharing. Exhaust a small finite example, with
full recombination and untouched components. Show that zero noise or public
support reveals a query syndrome. Implement a tiny clean-information-set
recovery example with a known full-rank code. These are explanatory controls,
not attacks on existing production masks or reviewed schemes.

Count all integer k/tau choices for eight retained geometries. Exact clean-set
success is binom(n-tau,k)/binom(n,k), before rank/inversion work. Report its
trial exponent, separately from total attack work/security. Also report secret
guessing entropy k*log2(t), which is only a necessary filter. The 128-bit trial
screen is deliberately a filter, not an approved security criterion. Retain
the largest trial exponent of any recipe with at least 20% expected row-work
saving. Preserve rejected/noiseless/public-support cases.

Stop this one-level public-code recipe before large HE/native implementation
if the claimed row saving forces a cheap clean-set attack, poor entropy or
extra state/work that overwhelms it. Recursive/programmable recipient-specific
PCGs, secret-code EMVP and trapdoored verification are different constructions;
leave them open rather than generalizing this negative into an impossibility.
Return to R6 and the R2 matched acquisition control afterward.
