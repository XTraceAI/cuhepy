# E49: encrypted-index correlation factory, with a decisive stronger control

2026-09-30. [Encrypted factory](../../experiments/bfv_search_lab/ciphertext_factory.py),
[vectorized plaintext control](../../experiments/bfv_search_lab/coordinate_factory.py),
[benchmark](../../benchmarks/ciphertext_factory_lab.py). All remain local,
volatile research modules. This is P03/P10 screening, not the gated P08 service.

## Construction and limitations

Instead of computing and freshly encrypting every plaintext `M*r`, a trusted
factory computes `Y_r=sum_j C_j*alpha_j(r)+Enc(0)` with the existing homemade
native arithmetic. It retains the encrypted index; it receives no plaintext
coordinate matrix in its preparation call. The pad r stays inside that trusted
local boundary. Sending r to the untrusted compute server/GPU would reveal the
private transformed query after delta is released.

The factory releases the **complete** ciphertext coefficients. The zero
encryption's seed stays private. A regression deliberately exposes that seed
in a tiny one-column example: subtracting its public C1 lets the server solve
for r, then recover the query from delta, without the HE secret key. Consequently
the E48 public-seed recipe cannot simply be applied to this zero encryption.
Every genuine output still passes the complete original check before secret
decryption; malformed/forged and exhausted-token cases are tested.

Homomorphic evaluation adds noise, so this requires a stronger envelope than
the original fresh plaintext factory. For every reply, let
`K=sum_j degree_j*floor(t/2)*column_phase_j`. Publish the same bound for all
pads: answer `B_fresh+K`, complete response `B_fresh+2K`. Reject before
preparation if twice that complete bound reaches Q. No pad norm is published.
Semeion/Q32 is already close to this limit; accumulated index repair is not a
free compatible extension. Rebase or a separately assessed larger Q may be
necessary.

The intended privacy hybrid requires **joint fresh-ciphertext pseudorandomness
with the honest index as auxiliary information**, followed by a uniform-pair
shift argument. Generic IND-CPA closure alone is not that argument. The toy
uniform-pair bijection is an algebra check, not an RLWE or circuit-privacy
proof. Published-seed index encryption still has the separate seeded-XOF
obligation in [P07](exact-search-security-game.md). The trusted factory has key
access, so no confidentiality from a compromised factory is claimed.

## First pilot and retained negatives

Four measured query pairs plus a warmup, identical public workloads/keys/circuit
and full checks, fresh independent pads. All scores/stable top-three, complete
native/GMP coefficients and unreduced integer phases agree.

| Fixture | Original plaintext production + answer check | Encrypted-index production + answer check | Prepared packet |
|---|---:|---:|---|
| Mushroom | 50.530 ms | 49.398 ms | 65,642 → 131,072 B |
| Semeion | 41.897 ms | 55.675 ms | 65,642 → 131,072 B |
| Synthetic rank-128, m=16,384 / d=512 | 181.034 ms | 54.156 ms | 82,026 → 163,840 B |

The synthetic isolated preparation gain is 3.34x; online time is unchanged at
about 57 ms. The extra trusted native setup costs 0.856 s, a modeled local-work
break-even around seven tokens before provisioning/network/state costs. The
factory retains a 20 MiB canonical encrypted-index body plus 32 MiB native
arrays, versus 512 KiB modeled two-bit plaintext coordinates (one-bit pivot
storage can be smaller). Those counts exclude GMP/Python resident overhead.
Semeion regresses; the Mushroom difference is too small to call a material gain.

## Stronger control: the initial speed claim does not survive

The original owner dot product used Python loops. A NumPy int8-coordinate /
int64-dot-product factory uses exactly the original fresh seeded encryption,
noise and one-use protocol. It retains 2 MiB of coordinate arrays in the
synthetic case; transient conversions are additional scratch.

| Same synthetic matched run | Production + check | Packet | Online work |
|---|---:|---:|---:|
| Original plaintext loops | 183.172 ms | 82,026 B | 56.359 ms |
| Vectorized plaintext | **38.136 ms** | **82,026 B** | 56.347 ms |
| Encrypted-index rerandomization | 53.900 ms | 163,840 B | 56.443 ms |

Vectorized plaintext is about **4.8x faster than the original** and about
**1.41x faster than the encrypted-index factory**, with smaller packets, less
retained state and the original phase envelope. Thus the 3.34x earlier gain
does not establish a new mechanism or justify promoting E49. It mostly
removes Python-loop overhead. This ordinary optimization remains useful for
the company baseline and as a stronger research control.

Return to the plan: keep E49 as a conditional encrypted-only preprocessing
alternative, not the primary speed contribution. Investigate lifecycle-aware
representation/noise/reserve decisions, and compare against vectorized owner
preparation. No security assumption, production path or GPU deployment is
promoted by this experiment.

Raw [Mushroom](../../benchmarks/results/publication-ciphertext-factory-mushroom-20260930.json),
[Semeion](../../benchmarks/results/publication-ciphertext-factory-semeion-20260930.json),
[first synthetic](../../benchmarks/results/publication-ciphertext-factory-synthetic128-20260930.json),
[strong synthetic control](../../benchmarks/results/publication-factory-vectorized-synthetic128-20260930.json).
Reproduce the stronger control with `.venv/bin/python benchmarks/ciphertext_factory_lab.py
--dataset synthetic128 --vectorized-control --json-out /tmp/factory.json`.
