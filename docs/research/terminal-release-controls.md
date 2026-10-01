# E66: compose pinned C1 recipes with supported C0 release

2026-09-30. Executed R1 control from the
[research plan](publication-research-plan.md). This combines known components;
it removes neither fresh answer generation nor trusted checking preparation.

Homemade [adapter](../../experiments/bfv_search_lab/terminal_release.py),
[tests](../../experiments/bfv_search_lab/test_terminal_release.py),
[runner](../../benchmarks/terminal_release_lab.py) and
[raw](../../benchmarks/results/publication-terminal-release-controls-20260930.json)
at source HEAD `1b4e525`. The
[supported relation](supported-decoder-relation.md) and
[recipe provenance](component-recipe-results.md) remain prerequisites.

## Checked relation and trust

The original request delta is already public in the fresh masked protocol.
The owner pins the fresh index's public C1 seed manifest and registers every
answer's public C1 seeds **before** its request. The server sends only certified
C0 coordinates. The client reconstructs the exact full C1 from those pinned
recipes, restores phase bounds from trusted registration, checks the separate
supported relation, then invokes the dedicated selected-phase decoder.

No reply field selects a seed, key, plan, bound, ID or epoch. The index/answer
seeds must actually reproduce their C1. Cached and streaming reconstruction
are distinct modes. Dynamic rerandomization and related factory-zero recipes
are unsupported; publishing those seeds is not justified by this adapter.
Malformed packets burn the same local attempt/token budget; rejected packets
never invoke the private decoder. Budget state is volatile, not durable.

This is output-relation soundness rather than equality to one full ciphertext:
altering an omitted C0 coordinate may leave the transmitted packet and exact
scores unchanged. Every influential C1 coordinate is still reconstructed and
checked. Neither a mod-t substitute nor unreviewed rounding is used.

## Results

Seven layouts, cached/streaming recipes and 16 binary queries per mode give
**224 exact encrypted searches**. Native selected decryption, independent GMP
phases and full BGV decryption agree with every score and stable ID. Negative
controls cover modified/truncated/extended packets, stale epochs, substituted
index/answer seeds, replay and exhausted budgets. The linked tests include
valid alternate omitted-C0 encodings.

Actual bitpacked bodies for the N=32, t=17 toy profiles:

| Layout / row counts | Full reply | C1 recipe only | Supported C0 only | Combined |
|---|---:|---:|---:|---:|
| Root / 19 | 256 B | 128 B | 204 B | 76 B |
| Leaves 0,1 / 12,4 | 256 B | 128 B | 224 B | 96 B |
| Leaves 0,10,11 / 6,3,1 | 256 B | 128 B | 184 B | 56 B |
| Multiple replies / 35,9 | 768 B | 384 B | 664 B | 280 B |
| Score layout / 12,4 | 256 B | 128 B | 224 B | 96 B |
| Dense / 16,16 | 256 B | 128 B | 256 B | 128 B |
| Empty first leaf / 0,4 | 256 B | 128 B | 160 B | 32 B |

The combined body is 12.5–50% of the full body in these toys. This is a
**response-body result**, excluding provisioning, keys, framing and setup.
The raw also prices added public seeds and cached native-word storage; a small
packet can cost more CPU/state. Stage timings are diagnostic only: this toy
run overlapped an upstream build, so no latency improvement is inferred.

Thirty-five release/decoder/recipe tests passed together; the later 51-test
selection additionally exercises operator and correlation controls.

## Remaining controls and decision

The follow-up [integer-phase oracle](../../experiments/bfv_search_lab/terminal_phase_packing.py),
[tests](../../experiments/bfv_search_lab/test_terminal_phase_packing.py),
[runner](../../benchmarks/terminal_phase_packing_lab.py) and
[raw](../../benchmarks/results/publication-terminal-phase-packing-control-20260930.json)
at `bd87bf2` price the exact unrescaled additive-HE control. All 729 N=2
negacyclic phase cases preserve signed bias and full-Q centering before mod t;
negative-borrow and Q-carry shortcuts fail. For secret bound eta_s, an integer
phase is conservatively bounded by (Q//2)*(1+N*eta_s). The packed limb must hold
the signed-bias interval before the additive modulus is used.

For a modeled 2048-bit Paillier modulus, all eight retained profiles give
**1.38–1.46× the full two-component reply** before keys/proofs/framing. The
selected Q32 profile produces 190,976 B rather than 131,072 B; the 16-reply
Connect-4 profile produces 365,056 rather than 262,144 B. Straight coefficient
encryption of a length-16,384 secret adds 8 MiB of key ciphertexts plus many
exponentiations. These key/work counts describe that simple method, not a
lower bound on every scheme. No additive crypto or timing is implemented.
Stop this raw phase-packing variant; ZipPIR rescaling and rate-1 constructions
are distinct controls and are not ruled out by this count.

Advance this adapter as the hard direct-fresh baseline for E68/E69. Its known
composition is **not** a paper novelty or a reduction of the per-query owner
factory. Do not silently transplant public recipes to a private outer query.

R1 remains open for ordinary LWE extraction/repacking, smaller terminal
contexts and applicable optimized independent-key compression. Each requires an exact
release relation and applicable noise bounds; terminal HE still needs matching
malicious integrity. Their construction-level obligations are listed in the
[cards](protocol-baseline-cards.md). A byte count alone does not close them.
Seeded privacy, full protocol proof, parameters, private-key timing and durable
state remain unreviewed; this lab is not a production receiver.

```bash
.venv/bin/python benchmarks/terminal_release_lab.py \
  --json-out /tmp/e66-terminal-new-run.json
```
