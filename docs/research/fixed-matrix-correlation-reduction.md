# E69: ideal random-triple conversion to the fixed private index

2026-09-30. R4 control of the
[research plan](publication-research-plan.md). The exact required output is
specified by the [correlation contract](authenticated-correlation-contract.md),
not merely a random matrix multiplication triple.

Homemade [oracle](../../experiments/bfv_search_lab/correlation_conversion_oracle.py),
[tests](../../experiments/bfv_search_lab/test_correlation_conversion_oracle.py),
[runner](../../benchmarks/correlation_conversion_lab.py) and
[raw](../../benchmarks/results/publication-correlation-conversion-controls-20260930.json)
at source HEAD `e9c91f8`. No PCG or distributed MAC is implemented.

## Ideal conversion and recipients

An ideal source gives a random B, uniform fresh r and z=B r over F_t. For the
fixed owner matrix M, the owner computes

```
y = z + (M - B) r = M r mod t.
```

The owner then embeds y using the prescribed CRT output map, samples fresh
bounded HE errors and encryption randomness, encrypts that output, and
registers the complete full-Q checking material. This is a complete algebraic
conversion **only under the ideal triple premise**. Recomputing B r in the
oracle is a diagnostic, not distributed authentication.

| Value | Permitted holder in this control | Server visibility / obligation |
|---|---|---|
| M, B, r, z and M-B | Trusted owner only | None; the generator is not an untrusted helper |
| r | Owner and authorized query client | Fresh, private provisioning; no repeated-mask transcript |
| y=M r and its centered lift / CRT embedding | Owner | Only the fresh answer ciphertext is released |
| Encryption errors, secret key and any private zero randomness | Owner | Remain private; no public related-seed shortcut |
| Encrypted index and fresh answer ciphertext | Server | Bind to the approved epoch/key/plan/token |
| delta=a-r mod t | Client and server | Ordinary public masked request; exact field lift preserved |
| Private challenges, fingerprints and answer check | Trusted verifier/client | Never provisioned to the compute server |
| Accept/abort | Declared public feedback | Must be covered by the eventual full protocol argument |

Owner and client can coincide and may retain their entire plaintext index.
Owner compromise is outside that confidentiality claim. A real two-helper
generator needs a separate corruption/noncollusion model. Moving B or M-B to a
helper without such a model changes the contract; matrix shares cannot be
treated as magically owner-private values.

## Executed controls and obstruction

All 81 matrices in F_3^(2x2), each with three sampled ideal triples, pass
**243 exact conversions**. Altering z is detected by diagnostic recomputation,
while unguarded conversion alone returns the wrong product. Thus valid triples
are a real prerequisite, not something this formula authenticates.

For a fixed 7x4 block matrix, N=32, t=17, eta=1, sixteen binary queries also
pass fresh owner encryption, native versus GMP evaluation, the existing
full-Q gate, exact score/ID decoding and one-use replay rejection. Sixteen
fresh C1 packets are distinct; that observation is not a distribution proof.
No field carry is dropped by substituting an F_Q mask or reducing a ciphertext
before the gate. The [operator control](structured-operator-results.md) also
rejects publishing the deterministic full-rank mask image.

For m rows, h coordinates and P tokens, this naive conversion still uses
**P*m*h field products** for (M-B)r: the same count as direct M r. It adds
P*m*h correction subtractions plus handling an ideal random matrix and its
product. In the encrypted toy this is 28 products per token, not a reduction.
Fresh answer encryption and full-Q checking preparation both remain. The
count excludes every cost of a real generator, expansion, authenticated setup
and private provisioning, so it is already optimistic for the proposed win.

This does not prove all correlated generators are ineffective. It rejects the
specific argument that ordinary random triples automatically remove fixed-M
preparation. Structure/batching could alter runtime; compare them to the
existing vectorized direct-fresh control instead of counting the ideal product
as free measured acceleration.

## Closest primitive and next decision

[Ring-LPN PCGs, §7.4](https://eprint.iacr.org/2022/1035.pdf) discuss bilinear
matrix applications and expansion costs. [Any-field PCGs, §7.2](https://eprint.iacr.org/2025/169.pdf)
give random matrix-triple/OLE applications over their specified subfields and
recipient shares. Neither application by itself programs an arbitrary private
M into our fresh encrypted token functionality.

**Stop this generic random-triple path as a preparation optimization.** Before
a homemade PCG implementation, select a precisely defined programmed
construction and show that fixed-M programming, expansion and the conversion
save a complete cost term. Its actual setup, field constraints and security
theorem must be reviewed. A seed sampler is not a PCG. A share-domain release
or a two-helper alternative is a changed protocol requiring a separate proof.
R4 remains open for those alternatives; this bounded rejection is complete.

```bash
.venv/bin/python benchmarks/correlation_conversion_lab.py \
  --json-out /tmp/e69-correlation-new-run.json
```
