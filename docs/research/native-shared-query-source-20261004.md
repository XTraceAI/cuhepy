# Q76.3b registered source-scale correctness return

The registered large correctness gate passed: one fresh HE key and exactly
six searches, two each at 8224, 16384 and 32768 vectors. Read the
[machine-readable return](native-shared-query-source-return-20261004.json)
and [original registration](native-shared-query-registration-20261004.json).
Executed source commit is `3315080`; source/archive/library hashes pin its
exact bytes. This is a correctness result, not a timing or security study.

## Checked behavior

| Gate | Result |
| --- | --- |
| Whole-Q independent arithmetic | All 50,626,560 canonical source/output coefficients across six transcripts match the independent GMP producer byte for byte. |
| Complete compact frames | Every native frame equals independent exact GMP rounding/framing. |
| Public authority | Every original query and complete response passes owner authentication, complete native admission, current snapshot and durable callback claim before private diagnostics. |
| Exact search | All 114,752 distances agree with the independent packed-binary XOR/popcount oracle. |
| Physical padding | All 131,072 phase positions in each of Q and P are checked; 16,320 unused positions per modulus decrypt to zero. |
| Stable ties and IDs | Deliberate exact ties return positions 0/1/2 or 3/4/5, with complete descending UInt64 IDs preserved. |
| Local lifecycle | All six attempts finish delivered; six authorizations and callback claims, no reset/retry. |
| Final selected regressions | 258 passed: 59 GMP producer + 2 public fixture + 197 existing native/auth/lifecycle cases. Two intentional fork warnings, no skips. Earlier overlapping invocations are not added. |

The profile is unchanged: N16384, dimension512, t1031, eta21,
ordered primes `(1152921504606748673,1152921504606683137)`, their actual
120-bit product Q, P33548413, owner origin, canonical radix30 and native
paired Karatsuba. The independent GMP backend uses four direct products,
whole-Q Kronecker convolution and separately written expansion/permutation/
framing. The small reference's N>64 guard remains intact.

Private setup was necessary for this fresh cohort: one HE key, 40 public
evaluation-key columns, 2048 owner-encrypted index ciphertexts and six fresh
query ciphertexts. Owner-only variable-time diagnostics check full Q/P
phases, public-box bounds, all scores and tails **after** the response has
passed public authorization and its callback claim is committed. No HE
secret or supporting Ed25519 secret was serialized. The server receives no
private diagnostics. These operations are research code, not the eventual
reviewed constant-time private client.

The raw cohort field `all_full_Q_and_compact_P_coefficients_checked` counts
the **two decrypted phase vectors**, not four ciphertext component vectors.
The return records that qualification; complete ciphertext/source bytes were
independently compared before admission. Original executed artifacts remain
unchanged.

## Resources and interpretation

Raw relation bodies are 126,320,640 bytes for one group and 127,057,920 bytes
for two. These are internal untrusted-evaluator-to-verifier witnesses, **not**
the compact client response. Native cached public rows are 423,624,704 or
826,277,888 bytes; maps/shifts add 3,538,944 bytes. The cache stays under the
registered 1GiB limit. Keys, original buffers, graph, scratch, wire copies,
owner work and process memory are additional paid quantities.

The observed whole-process high-water RSS is 3,406,163,968 bytes at the
largest case. It includes owner setup, GMP and native arithmetic, buffers
and private diagnostics; it is not isolated native peak accounting or a
protected-deployment measurement. Runtime duration is not used as a timing
sample. No CUDA port or timing panel ran.

This establishes one large-key correctness gate. It does not establish
concrete cryptographic security, private side-channel assurance, real TEE
attestation/freshness, a complete service speedup or an original paper result.
The 54 production source files, 12 delivered libraries and local main/staging
refs remain byte exact to the preservation baseline.

## Reproduction and next task

`benchmarks/source_shared_query_lab.py` requires an explicit isolated library,
the successful GMP-preflight receipt and a **new** output directory. The
complete source archive is frozen before the single key attempt is consumed.
The runner preserves failed/partial attempts and cannot silently overwrite
or restart its cohort. Exact public input/enrollment/request/reply bytes,
source archive, six receipts, local journal and logs are retained in
`/home/pete/yavor-projects/xtrace-work/research-data/q76-source-scale-20261004/`.
Do not generate another key just to reproduce this passed gate; reuse public
artifacts for the next control tests or register a justified new cohort first.

Return to the [execution plan](system-contribution-execution-plan-20261004.md):
next is **Q76.4 matched prepared replay, checked-product/protected suffix and
permitted cache**, then **Q76.5 independent certificate/resource/boundary
handoff**. The [product-control card](native-shared-query-product-control-card-20261004.md)
now records aggregate degree-two, full actual-prime checks and assurance-cost
qualifications. Prepared replay must omit unnecessary witness serialization;
every compatible control receives the same optimizations. Q77 timing stays
conditional on those remaining gates. The scientific target is the useful
complete-cost design choice and its assurance, with known ingredients and
cache wins explicitly retained.
