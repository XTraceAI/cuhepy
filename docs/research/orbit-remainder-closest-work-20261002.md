# E90 targeted precision and authentication controls

2026-10-02. Source versions are pinned in the archive. No author artifact,
published speedup, parameter claim or full proof audit is reproduced here.

[Meta-PBS](https://eprint.iacr.org/2025/2284): targeted Definition3,
Algorithm1/Theorems1–3, section5/Definition4/Lemmas5–6 and AppendicesD/E,
including Table12. Its unreduced quotient preserves an integer phase
identity. Locally negacyclic column merging already reduces packing work
and key storage, with garbage-coefficient support and noise conditions.
Some packing keys can be reused across iterations; centering shifts need
not be embedded. These are strong controls, not new mechanisms here.
Binary input secrets, Gaussian approximation/independence and divisible
moduli are premises; they do not automatically hold for our evaluated BGV
product, signed orbit keys or auxiliary-key distribution.

[Ciphertext drift](https://eprint.iacr.org/2024/1718): added primary
EUROCRYPT2025 paper. Public rounding-error screening and rerandomization
are prior controls; full acceptance/failure security differs from IND-CPA.
Do not infer safe feedback or parameter assurance from a public arithmetic
check. Targeted reading of the relevant definitions and sections4–6 follows;
the stored revision and tie convention must be identified before adaptation.

Generic full recomputation and existing hoisted/common-subexpression proof
circuits receive exactly the same orbit sharing as the candidate. The
implemented receiver pays the full public subrelation, and proves neither
the original encrypted scores nor lookup/ID coverage. HasteBoots, general
vFHE, full-score release and permitted caches remain complete competitors;
unavailable adaptations are open costs, never zero.

The new candidate is narrowly the exact multi-stage signed carry/tie law and
its binding. The sharp rounded-grid count is a derived restricted lemma;
priority and a useful complete-system consequence are unestablished.
