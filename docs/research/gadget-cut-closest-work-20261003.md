# Q64: propagated gadget cuts and closest controls

This is a targeted mechanism review, not an exhaustive novelty search. The
candidate and finite execution queue are in
[the registered plan](gadget-cut-research-plan-20261003.md). The first literature
download failed sandbox DNS; both retrieval receipts are retained. Three primary
PDFs, extracted text, hashes and inspected pages are archived in
`../research-data/gadget-cut-research-20261003/primary/`. No author artifact or
performance result from these papers has been reproduced in this cycle.

| Control | Established result relevant here | Required adaptation / distinction |
| --- | --- | --- |
| Kim, Kwak, Lee, Seo and Song, [homomorphic gadget decomposition](https://eprint.iacr.org/2022/347.pdf), §§4.1–4.2, 6.2–6.3 (PDF pp9,17) | Any sufficiently bounded representation in the gadget inverse image can replace canonical decomposition. Addition works for arbitrary gadgets; componentwise multiplication requires the special gadget property. Their RNS construction uses CRT idempotents, and enlarged special moduli offset increased error. | Our radix gadget must retain all cross terms, not apply the RNS componentwise identity. Give this control the same propagated representations and public composite-key fusion. Our fixed Q120/P25 cannot silently gain an enlarged modulus. The algebra is known; the packing/verification schedule remains to be tested. |
| Belorgey, Carpov, Gama, Guasch and Jetchev, [bivariate decomposition](https://eprint.iacr.org/2023/771.pdf), §3, Algorithm1, §3.1 comparison (PDF pp11–15) | Limb precision and cyclotomic arithmetic can be separated. Integer vector carry normalization and public decomposed products are established techniques; precision, norms and normalization costs remain explicit. | Unnormalized public digit products are not a new representation. This control receives the same decomposition, convolution backend and fusion opportunities. Our question is whether a bounded interval without normalization removes verification cuts at useful complete cost. |
| Mono and Güneysu, [BGV matrix triples](https://eprint.iacr.org/2023/593.pdf), §4.4 (PDF p20) | Lazy switching accumulates multiplication outputs before one switch; hoisting/pre-rotation trade memory for repeated work. | Preserve these opportunities for the canonical control. Propagated digits change the subsequent switch representation while switching at every chosen stage; they are not a new lazy-switch primitive. Compare source cuts, producer work and public preprocessing separately. |
| Repository E20, E81 and E110 | E20 preserves automorphed secret terms with extra keys; E81 already accepts bounded common noncanonical digits with exact no-wrap decoding; E110 public/functional key compilation was contained by known methods. | The proposed unary anchor uses existing keys and changes the evaluator relation. Do not revive the rejected primitive claims. Ordinary public composite-key fusion is a control, not a contribution. |

The conditional systems hypothesis is precise: an entirely unary butterfly
stage lets its checked switching source also determine its plus input. Propagate
its common integer digits through public key-A digits into one next stage.
This may eliminate a later canonical source cut without an extra plus witness.
A binary anchor lacks that information. Q65 must show the distinction with a
counterexample, exact common-integer relations, deterministic noise bounds and
a complete body/cost ledger. Q66 must then test actual homemade encrypted
outputs under those public guards.

**Q64 decision:** the propagation identities and public fusion are established
methods. The geometry-dependent verification-cut policy is an unestablished
systems candidate, not accepted originality. Stop if the fixed profile fails
its public guard or complete cost, or if a targeted published adaptation already
provides the whole claimed schedule. A useful schedule alone would still need
broader closest-work review, an implemented complete admission path and a
measured system comparison before a paper claim.
