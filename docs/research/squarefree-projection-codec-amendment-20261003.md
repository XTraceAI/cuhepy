# E119 codec clarification before the registered cohort

2026-10-03. The [original preregistration](squarefree-projection-preregistration-20261003.md)
remains unchanged. Read-only peer review found that Q5,t3,drop2 fails the
existing `QuantizerLaw` unique-centered added-error admission guard. Therefore
the fixed coefficient8 negative uses the **formal unadmitted rounding formula**
on limbs5/13, then CRT, only to falsify a blind substitution for the admitted
whole-Q65 codec. It is not a valid limb ciphertext codec or a backend attack.

Keep the same Q65,t3,drop2 and coefficient8, the same65-point whole-Q panel,
and all original mask/witness contexts. Also record the actual Q5 codec guard
rejection; never bypass it or construct an admitted limb-law object. Label the
formal comparison as unadmitted in code, tests, raw and report. No new
parameter, search, profile or runtime modification is authorized.

This clarification precedes the main source/argv freeze and cohort. Preserve
its external copy/hash, peer discovery record and all earlier prereg bytes.
