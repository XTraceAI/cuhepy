# R0: construction contracts and adaptation obligations

2026-09-30. Bounded construction review for the
[plan](publication-research-plan.md). Versions and targeted reading depth are
pinned by the [source registry](publication-literature-sources.json).
These are comparison cards, not independent proof/parameter reviews. Homemade
code remains the deliverable; author artifacts stay outside company modules.

Notation: our public ciphertext operator D has L=2RN rows, W actual query-form
coefficients and F column generators. Q and t are the **inner** ciphertext and
score moduli. An outer protocol has separate q_o, p_o and security dimension d.
Do not silently identify these fields. A lift of D uses centered Q integers;
an outer plaintext output must recover the prescribed Q residue exactly.

## 1. vReinsPIRe: reusable verification of the public response map

Source: [ReinsPIRe, §4.2–4.3, Algorithm 4, Theorems 5–9 and Appendix B.2](https://eprint.iacr.org/2026/1934.pdf).
Use the pinned September 2026 version, not an assumed later ePrint revision.
In our notation its CRS A is Wxd, digest H=D A, hidden binary challenge C is
kappaxL, Z=C D and Z'=C H'. H' is the public packing map derived from H/CRS.
The online server evaluates [D,H']u; [Z,Z']u=Cx is checked before remaining
local ciphertext completion/decryption. Registration uses an auxiliary LHE.

The full malicious theorem admits extracted matrices of infinity norm at most
2L*b when honest D has norm b; its SIS bound is (2L+1)*L*b. Underlying LHE must
be correct on that admissible class. The paper's experiments instead use an
honest-digest premise. Key-dependent RLWE, underlying query hiding and SIS are
separate assumptions. Reusable C/Z state must remain private under the stated
feedback game; successful output exposure is not silently added.

Paper formulas, with its dimensions renamed:

```
client-state bits <= 2L log2(q_o) + kappa W log2(L b)
                     + kappa ell d log2(q_o) + lambda
server preprocess = O(L W d + ell L d log d + underlying-LHE-preprocess)
server online field products = L(W + ell d)
client check/finalize = O(kappa(W + ell d + L) + L ell log d + L)
registration download = L d log2(q_o) + auxiliary-LHE-download
registration upload = auxiliary-LHE-upload
online upload = (W + ell d) log2(q_o); download = L log2(q_o)
```

These are construction bounds, not measured lower bounds. Seed regeneration,
streaming and packing change physical storage; do not assert that C must be
materialized. Server/client key switching masks and packing terms are paid.

**Our adaptation obligations:** D is already public encrypted data, but server
extraction binds its own chosen matrix, not automatically the owner-approved
epoch. The owner must pin a correct digest/CRS and the exact bounded lift, or
prove a binding adapter. This could specialize an honest-digest premise;
it is not a free claim of the general theorem. Hide both private query forms
and their result. Price outer q_o/p_o/noise and all H/H'/Z objects. Signed
negacyclic shifts, mixed subring embeddings and terminal projection are fixed
by the owner, not selected from a server response.

The pinned artifact path uses explicit matrices for database, hint and packing
operations. Fast forward/adjoint products handle D times a matrix and C D;
they do not yet instantiate GenPack, malicious extraction or LHE query hiding.
Those are the next R3 proof-interface discriminator.

### Actual pinned reproduction

Author [repository](https://github.com/google/InsPIRe), commit
`acab7853e8fe11a70b5fa40e17487f7429e82810`, unchanged tracked source. Local cache:
`../research-data/mechanism-references-20260930/InsPIRe`. Bazel 9.0.0 was downloaded
from its official release and checked against its SHA-256. Generated dependency
lock and binary/test/log hashes are recorded in the
[receipt](../../benchmarks/results/publication-author-vpir-control-20260930.json).

```bash
bazel-9.0.0 --output_user_root=/tmp/cuhepy-verifier-bazel9 test -c opt \
  --jobs=4 --test_output=errors \
  //crypto/vpir/client:vpir_client_test //crypto/vpir/server:vpir_server_test
```

Both targets passed: **5 client + 54 server individual cases**, zero failures,
errors or skips. Native types/profiles differ among the tests; target success
does not establish our requested construction or a parameter proof.

Also executed the author's metrics tool, N_entries=d=2048, one entry-size
multiple, kappa=40, three iterations, local_finalize=false, verification on.
It uses a random 4 MiB byte database and fetches record 123, not Hamming scores.
Each reply went through VerifyResponse/DecryptResponse; its correctness check
compares the **first** returned record. Reported status=1, mismatches=0.

| Author metric | Bounded local observation | Classification |
|---|---:|---|
| Server preprocessing | 6,973.85 ms | One measured setup stage |
| Offline server proof generation | 520.795 ms | Author timing boundary |
| Offline client processing | 3,358.04 ms | Author timing boundary |
| Online client query | 12.904 ms | Mean of 3 |
| Online server response | 10.251 ms | Mean of 3 |
| Online client verify + decrypt | 2.905 ms | Mean of 3 |
| Online query / reply | 73,728 / 8,192 B | Formula, no RPC |
| Offline client upload / download | 552,960 / 17,442,816 B | Formula |
| Client / server retained storage | 3,735,552 / 195,600,384 B | Formula, no RSS |

The tool's offline generation/client processing boundaries contain distinct
preprocessing calls; do not sum them into a matched end-to-end service result.
Its online plaintext modulus is 256, modulus=0 denotes its uint32 arithmetic,
variance=11; auxiliary q=2^54, p=2^24, variance=40, gadget base bits=11/5 digits.
Kappa=40 is not our 128-bit lifetime target. Build warnings and dependency
resolution are retained. No paper table or full malicious experiment is
claimed reproduced. **Assigned gap P01/R3:** arbitrary-form, full-Q operator
adapter, admissible correctness, owner binding and matched score/ID workload.

## 2. Small-state vLHE: privately evaluated decryption correction

Source: [Verifiable PIR with Small Client Storage, Figure 5, §3.1–3.4, Theorem 3.11 and Appendix A.2](https://eprint.iacr.org/2025/1714.pdf).
Same CRS/digest notation. Offline encrypted binary C produces Z=C D;
norm and Z A=C H are checked. Online u masks the private plaintext query;
server returns v=D u and an FHE encryption of Hs. The client uses a **fresh
auxiliary key** per query, decrypts that correction, checks both equations and
then releases the main result. The simulation and correctness premises govern
that key use; this is not permission to decrypt arbitrary replies with our
long-lived inner key before verification.

For honest entry bound b, choose B>=L*b; extracted D has norm <=2B, and SIS
bound is (2L+1)B. Correctness on that class is required. Its prime-field state
compression retains Z'/C' with gamma=ceil(kappa/log2(q_o)):

```
proof state = gamma(W+L) log2(q_o) bits
online server = D u + FHE evaluation of H s
online client = fresh auxiliary key/query + decrypt Hs + hidden linear checks
offline paid objects = H (Lxd), encrypted C (kappaxL), Z (kappaxW), FHE keys
```

This replaces a large retained hint, not all its evaluation/setup costs.
Registration must be owner bound as above. Its compressed private challenge
state and observable feedback need the original argument; our one-use budget
cannot be called a reproduction of that reusable theorem. Covert/stateless
client mode has a different detection/availability contract.

Artifact [repository](https://github.com/mayank0403/Verifiable-Hintless-PIR), pinned
`56b8b744276aa3f3c078509501200967d28cfc7b`. Inspected, **not executed** in this
tranche. The README limits its ordinary database to 8-bit plaintext and states
an honest hint assumption. Its default test has a 512 MiB database; FAKE_RUN
skips real preprocessing. Do not use it for complete costs. **Assigned gap
P01:** bounded honest run, then actual full-Q/field and client-state adaptation.

## 3. EMVP: hidden private matrix and compressed correction

Source: [EMVP, §2.1, §4.1 and §7.4](https://eprint.iacr.org/2025/858.pdf), pinned
2026-08-24 full version. The client owns M and secret code/trapdoor data; the
server has its encoded matrix. Query privacy is over the chosen field, under
the paper's secret-code/noisy-sample assumptions and parameter analysis.
The ordinary primitive is not our malicious pre-decryption service gate.

Its linear output-correction form is Mq=M'p'-r'. Section 4.1 permits encrypting
that short correction with additive HE and evaluating it without another
round; that changes field/decoder and adds keys, homomorphic work and output
decryption. Price encoded rows/columns, trapdoor/client matrix, query code
length, correction dimension and any added full-reply checker. Neither
uncompressed response timing nor a cache that retains M is the strongest
low-state/compressed comparator by itself.

The [original author reproduction](original-emvp-results.md) already records
cached/key-only modes, source pin `856762f5925fe873bb5cbc0401ceb5a44568efa9`, native
exact Hamming adapter and separate added private gate. Its observed cached
5.94/1.36 ms and 1,471,264/205,100 B Mushroom/Semeion points are **different
profiles/contracts**, not a ratio against this tranche's vPIR/cache timings.
**Assigned gap P01/R1:** implement the specified additive-HE composition and
matching malicious transcript argument; reassess entropy/field parameters.

## 4. Recursive BNTM: reusable private setup with audit semantics

Source: [BNTM, Protocol 3, §7.1–7.2 and Appendix A](https://arxiv.org/abs/2502.13060).
Client setup contains iterated thin LPN matrices/trapdoors and encoded-private
matrix state; its verification authenticates outsourced setup. Honest noise
cancels exactly. The theorem uses its LPN premise and computational
zero-knowledge argument. A bad online fraction alpha is detected by roughly
O(1/alpha) audits; this is different from gating every untrusted inner reply
before a long-lived secret is invoked. Do not equate the two services.

For its mxn matrix and query batch width l, Appendix A gives client online
O(l(m+n)(nu+n^epsilon)), server dense mxnxl multiplication plus recursive
partial-product overhead. Initialization depends on the full recursion and
fast-multiplication exponent omega; it is not zero cost. For the square
matrix-vector case its stated extra server term is O(delta*n^2), with client
O(n(n^epsilon+nu)). This includes a stronger low-state tradeoff than ordinary
matrix multiplication with retained plaintext; parameter/domain constraints
still require review.

The [unified reproduction](baseline-reproduction.md) executed simpler modes,
not Protocol 3. **Assigned gap P01/P07:** find/adapt the strongest author
recursive construction and explicitly compose its auditing with observable
abort. Unavailable implementation is a gap, not evidence it is slower.

## 5. Terminal release: required honest controls and proof boundaries

| Control | Exact decoding/key/noise premise | Paid objects and missing work |
|---|---|---|
| E48 + E64 → E66 | Fresh owner-pinned public C1 recipes; selected full-Q phases; supported gate before inner secret | [Executed 224-query body control](terminal-release-controls.md); all fresh preparation remains |
| LWE sample extraction / repacking | All C1 terms for selected phases, with the exact secret transform and Q centering | n inner-key coefficients per ordinary extracted phase before amortization; extraction alone does not produce small packets |
| Smaller independent terminal context | Proved switching/rounding and exact score range; owner-pinned release relation | New/evaluation keys, switch work, terminal proof/check and private decryption; no admissible parameter tuple established here |
| [ZipPIR, §3–4](https://arxiv.org/abs/2303.09043) | Independent additive-HE encryption of LWE/RLWE secret, linear phase evaluation and justified rescaling | Compression key, packing bounds, signed carry, exponentiations and output decryptions; no matching malicious release implemented |
| [Linear-decryption rate-1 HE, §4](https://eprint.iacr.org/2019/720.pdf) | Separate compressor/decoder, valid input distributions and terminal capabilities | High-rate LHE assumptions, keys/work and composition; rate statement alone is not our receiver theorem |
| [HELIOPOLIS, §3.1 and construction](https://eprint.iacr.org/2023/1949.pdf) | Its verifier privacy explicitly excludes verification-feedback/subsequent-output oracles | Strong compression/verifier reference; feedback contract differs and no artifact run is claimed |

Full-Q inner responses cannot be reduced to t and rounded homomorphically
without a separate argument. A secret-key switch only changes which oracle
must be protected. The existing carry, C1 influence and public-related-seed
counterexamples are mandatory for every adapter. Retained setup and private
provisioning cannot be omitted from the acquisition panel.

## 6. Go/no-go after contract closure

R0's bounded cards and selected author unit/native control are complete; P01
and P07 remain open. These cards make the precise adaptation gaps explicit.
Next execute R3's H/Z/packing operation map, continue R1 applicable terminal
screens, and close R2 with matched private provisioning. Any resulting
construction still needs its own reduction and useful resource margin. The
large outer-field/hint/admissibility costs forbid promoting a generic nested
wrapper merely because its matrix multiply is fast.
