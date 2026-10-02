# E87 closest switching and authentication controls

2026-10-02. Targeted primary reading, not proof/parameter/artifact audits.
The PDFs/text and hashes are in the [archive](prior-work-archive.md).

| Control | What is already supplied | Difference the proposed system still needs |
|---|---|---|
| [New Secret Keys for Enhanced Performance in (T)FHE](https://eprint.iacr.org/2023/979), current revision | Sections 3.2.1/3.2.2/3.2.5, Algorithms 1–3: inverse constant extraction, partial-GLWE polynomial switch and extraction; Remark 4 charges forward/inverse FFTs and pointwise products. Theorems 2/5 include gadget, key and FFT errors. Section 4 studies related nested secrets. | The E87 scalar-column identity is not this paper's identical key format, but its arithmetic is ordinary polynomial switching. Switching the packed input once is the stronger control. Our correlated S² keys and chosen prefix/noise parameters are unreviewed. No authentication supplied by the arithmetic. |
| [HERMES](https://eprint.iacr.org/2023/1244), sections 4.1–4.5, Tables 3–5 | LWE→RLWE packing through MLWE midpoints; column method is a special case. A midpoint reduces elementary keys from K to K/k+k, with charged extra ModUp/Down/Hadamard work. These are large polynomial keys, not single field elements. | Its direction and key/noise/security constraints differ. Cannot assign its square-root key bound to arbitrary coefficient→scalar switching or our authenticated selection path. |
| [Sharing the Mask](https://eprint.iacr.org/2025/2112.pdf), sections 3/4/5 and Algorithm 10 | Matrix-key ciphertexts share a mask across bodies. CM versions of TFHE operations and packing are already defined. Algorithm 10 requires per-slot/per-source-coordinate switching keys; Table 7 prices CM key formats. | Extracted score masks are rotations, not identical masks under independent secrets. A free change to CM and its published parameters is not justified. Original-ring correlated orbit keys are a separate question. |
| CHIMERA / once-packed switch / streamed extraction | Known functional switching and packed polynomial arithmetic, followed by exact coefficient extraction | Pay compatible targets, message permutation, error and evaluator keys. Views/streaming avoid a scalar-output allocation without inventing a new cryptographic scheme. |
| E70–E72 / general vFHE / HasteBoots | Known quotient tests, output batching, compiled dense checks, or arguments for public FHE/PBS execution | Original-input/digit/limb binding, durable challenge order, all PBS/selection/IDs and verifier state must be included. Bare evaluations are not commitments. |

Rendered complete relevant pages checked: 2023/979 pages 14–15; HERMES page
23; common-mask pages 10 and 19. Text was also read around the algorithm,
noise, cost and key-format passages. The current 2023/979 title/section
numbering differs from the earlier lead; that lead is retained as history.
No published speedup is imported as a local measurement.

**Reading return:** price the stronger once-packed partial-GLWE control,
not only independent scalar switches. Test the exact signed-digit identity
and full recomputation as controls. An original cheaper *complete* digit/
input/PBS/coverage relation is still required to pass the main mechanism gate.
