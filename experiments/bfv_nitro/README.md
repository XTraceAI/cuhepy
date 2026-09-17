# BFV on AWS Nitro Enclaves

This optional experiment runs the existing public C++ RNS evaluator inside an
AWS Nitro enclave. The owner checks attestation and a signed response receipt
before decrypting locally. Each request performs one complete search. The
existing Paillier, BFV, SEAL example and owner-recomputing verifier remain usable
through their existing APIs.

This is an implementation for review and hardware testing, not a production
security certification. Local tests and benchmarks do not establish that an EIF
boots correctly or how fast it runs on EC2. See
[`docs/research/native-bfv-nitro.md`](../../docs/research/native-bfv-nitro.md)
for the protocol, evidence and remaining review work.

## Files and trust boundary

| File | Responsibility |
| --- | --- |
| `src/xtrace_sdk/x_vec/crypto/bfv_attested_client.py` | Owner authorization, attested client/server sessions, receipt gate and protected client state |
| `src/xtrace_sdk/x_vec/crypto/bfv_nitro.py` | AWS certificate/COSE verification, owner PCR policy and official NSM C-library adapter |
| `service.py` | Fixed-policy evaluator entrypoint inside the enclave |
| `transport.py` / `relay.py` | Bounded framing and untrusted TCP-to-vsock forwarding |
| `client.py` | Owner-side synthetic end-to-end demonstration |
| `Dockerfile` / `Builder.Dockerfile` | Public evaluator container and optional local EIF build tooling |
| `benchmarks/bfv_nitro.py` | Local protocol benchmark or real-enclave RPC benchmark |

The owner holds the BFV secret, an independent Ed25519 request-signing secret,
and the private distance-check summary. The enclave receives only public BFV
keys, encrypted vectors, owner-signed requests and the existing transport MAC
key. That MAC key is visible to the host and is **not** an owner credential.
The enclave creates its own ephemeral receipt-signing key using NSM entropy.
It does not receive an owner decryption key or expose a general signing API.

The measured service supports one owner, one immutable index and one active
attestation session. The host can interrupt, replay or replace traffic and can
deny service. The client accepts only evidence for its approved code, actual
setup digest, owner identity, execution policy and index epoch.

## Build on an owner-trusted Linux machine

Run these commands from the repository root. Install the optional client
dependencies and compile the existing native kernels:

```bash
uv sync --extra bfv-nitro
make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON="$PWD/.venv/bin/python"
docker build -f experiments/bfv_nitro/Dockerfile -t xtrace-bfv-nitro:research .
```

The Dockerfile pins base-image digests, a hash-checked official AWS NSM source
archive, Cargo dependencies and Python wheel hashes. It compiles only the
**public** BFV extension into the service image. Its restricted build context
excludes local binaries, test attestors, keys, indices, `.env` and git metadata.
OS packages still come from signed distribution repositories; this recipe does
not promise bit-for-bit reproducible builds. Review each resulting EIF and its
measurements through an owner-trusted release process.

AWS supports building EIFs on Linux outside AWS. Running one requires a
compatible EC2 parent with Nitro Enclaves enabled.
[AWS build command](https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-build-enclave.html).

If `nitro-cli` is installed on the trusted builder:

```bash
mkdir -p experiments/bfv_nitro/artifacts
nitro-cli build-enclave \
  --docker-uri xtrace-bfv-nitro:research \
  --output-file experiments/bfv_nitro/artifacts/xtrace-bfv.eif \
  > experiments/bfv_nitro/artifacts/measurements.json
```

Alternatively, the included builder container installs the official Amazon
Linux Nitro CLI. Its only host mounts are the local Docker socket and the
output directory. Treat the builder as trusted tooling: Docker socket access
confers control over the local daemon. No AWS credentials are needed.

```bash
docker build -f experiments/bfv_nitro/Builder.Dockerfile \
  -t xtrace-bfv-nitro-builder:research .
mkdir -p experiments/bfv_nitro/artifacts
docker run --rm --network none \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  --mount "type=bind,src=$PWD/experiments/bfv_nitro/artifacts,dst=/out" \
  xtrace-bfv-nitro-builder:research build-enclave \
  --docker-uri xtrace-bfv-nitro:research --output-file /out/xtrace-bfv.eif \
  > experiments/bfv_nitro/artifacts/measurements.json
```

Keep the measurement JSON on the owner machine. The client requires nonzero
PCR0, PCR1 and PCR2 from this trusted build. Additional PCR pins are checked
conjunctively. Do not replace these values with measurements supplied solely by
the untrusted hosting endpoint. A rebuild can change the PCRs; it needs explicit
owner review and a new policy. Exact image pins are mandatory even for an EIF
signed with a release certificate.
[AWS measurement definitions](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html).

The audited local amd64 build is recorded in `build-record.json`; its EIF,
measurement JSON and independent `describe-eif` output are in `artifacts/`.
That record can also be passed to `--pins`, since it contains the same
`Measurements` object. It refers to that particular build, not future rebuilds.
The EIF has no image-signing certificate; runtime AWS attestation is still
mandatory. No real enclave execution is claimed by a successful local build.
`build-record-before-audit.json` preserves the earlier build for comparison;
its measurements do not match the rebuilt artifact. See the
[code audit](../../docs/research/native-bfv-code-audit.md) for validation and
updated local measurements.

## Run the pilot on an existing Nitro-enabled EC2 parent

Transfer the EIF to a compatible parent of the same architecture. On Amazon
Linux 2023, install `aws-nitro-enclaves-cli` and
`aws-nitro-enclaves-cli-devel`. Configure
`/etc/nitro_enclaves/allocator.yaml`, add the operator to the `ne` and `docker`
groups, and start the allocator and Docker services as described in
[AWS's installation guide](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).

For an initial pilot, reserving 4 vCPUs and 8,192 MiB is a conservative starting
allocation to measure, not an established memory requirement or minimum. Leave
sufficient resources for the parent. The review-profile setup and preprocessing
need substantially more memory than the allocator's small default. The current
evaluator runs requests serially; this allocation does not imply four-way BFV
parallelism.

Launch the reviewed artifact, substituting its actual path:

```bash
nitro-cli run-enclave --enclave-cid 16 --cpu-count 4 --memory 8192 \
  --eif-path /path/to/xtrace-bfv.eif
```

Do not add `--debug-mode` or `--attach-console`: zero/debug measurements are
rejected by the client. Record the enclave ID for later lifecycle operations.
The enclave listens on vsock port 5000. From a checkout on the parent, run the
stdlib-only relay with Python 3.10 or newer:

```bash
python3 -m experiments.bfv_nitro.relay --cid 16
```

The relay binds `127.0.0.1:9000`. On the owner machine, establish an authenticated
tunnel using your normal SSH identity and host-key verification:

```bash
ssh -N -L 9000:127.0.0.1:9000 ec2-user@YOUR_PARENT_HOST
```

Then, from the owner's SDK checkout:

```bash
.venv/bin/python -m experiments.bfv_nitro.client \
  --pins experiments/bfv_nitro/artifacts/measurements.json --vectors 32 --queries 3
```

The demonstration generates synthetic data and fresh private keys locally,
uploads the signed public setup, verifies AWS evidence, and checks every
returned distance against the known synthetic answer. It prints the closest
three locally. It sends no result-acceptance or decryption feedback to the relay.

Start a **fresh empty enclave** for each invocation of the demonstration,
integration test or benchmark: each registers a new immutable owner/index.
Registration is self-authorized by its first owner. Hosting/account admission
controls remain a deployment responsibility; a malicious parent can claim an
empty service first and cause denial of service. It cannot make the legitimate
client approve that other owner's setup.

## Sessions and application integration

The deployed entrypoint fixes `bfv_review_policy()` and the `residue` backend:
N=16,384, 512-bit binary vectors, t=65,537, 180-bit coefficient modulus, existing
error distribution, and 50-bit terminal response modulus. The peer cannot
request alternate code, a weaker parameter set or a different backend.

The owner API follows the existing session clients:

```python
setup = client.prepare_index(vectors, vector_ids=vector_ids)
remote.register(client.registration_packet(setup))
client.accept_attestation(*remote.attest(client.begin_attestation()))
query = client.begin_query(query_vector)
distances = client.finish_query(*remote.search(query))
```

Renew attestation with the same two handshake calls before the five-minute
lease expires. Renewal retains the imported index, discards pending client
queries and replaces the active session. Complete outstanding work first.
Enrollment has a 30-second client deadline; evidence can be at most 120 seconds
old, with 5 seconds of future clock tolerance. Certificates are checked against
the owner's clock. A failed enrollment never enables decryption.

At most 1,024 enrollment nonces are retained per enclave instance; query and
resource budgets also remain bounded by the existing execution policy. Exhausted
budgets require a planned new instance/session state, rather than silently
disabling checks. A restart loses public preprocessing and its receipt key;
re-upload the setup and attest the new key. Index replacement uses a new
instance and owner-maintained epoch.

`protect_state()` encrypts the BFV secret, owner request key and verification
state under an independent wrapping key. It does not preserve an attested
session. `restore()` requires the expected setup, epoch and policies from owner
configuration and always requires fresh attestation. Keep the expected epoch
durably outside rollback-prone backups; encrypted state alone cannot detect
restoring an entire old owner configuration. Use a separate local workflow for
policy migration. Do not catch rejection and fall back to a raw decrypt API.

This service is an explicit experiment. It is not yet connected to the existing
production XTrace HTTP endpoints, multi-tenant storage or deployment automation.
The underlying circuit returns packed distances; top-k selection remains local.

## Tests and benchmarks

Offline tests use a synthetic CA only through test-local monkeypatching. The
public client has no custom-root or fake-attestation option. Tests also include
an authentic historical AWS document and the official NSM C ABI via a test shim.

```bash
uv run --extra bfv-nitro pytest tests/x_vec/test_bfv_nitro.py \
  tests/x_vec/test_bfv_attested_client.py tests/x_vec/test_bfv_nitro_transport.py
uv run --extra bfv-nitro python benchmarks/bfv_nitro.py \
  --mode local --num-vectors 1024 --repeats 4 \
  --json-out benchmarks/results/native_bfv_nitro_local_1024.json
```

The local benchmark checks identical ciphertexts with the baseline and includes
real certificate/signature verification against a **test** CA. It measures no
hardware isolation, NSM, vsock or cloud overhead. The report distinguishes the
one cold trial from the three warm trials.

Against a fresh real enclave and a running tunnel:

```bash
XTRACE_BFV_NITRO_PINS="$PWD/experiments/bfv_nitro/artifacts/measurements.json" \
  uv run --extra bfv-nitro pytest tests/x_vec/test_bfv_nitro_aws.py -v
```

The real test skips unless configured and cannot be satisfied by a synthetic
root. For a separate fresh enclave, use `benchmarks/bfv_nitro.py --mode aws
--pins PATH --num-vectors 1024 --repeats 20`. AWS-mode search timings include
relay and network latency; the comparison evaluator runs on the machine
invoking the benchmark. Comparing hardware overhead requires a matched cloud
CPU and compiler configuration. Measure enclave memory separately from the
benchmark's combined-process RSS.

## Security review still required

Attestation authenticates a measured program under AWS Nitro's trust model;
it does not prove that program correct. The current trusted software includes
the kernel/bootstrap, CPython, SDK imports, native extension, parsers and all
dependencies in the image. Reducing that dependency footprint is further work.
The service excludes a remote shell, configurable execution or host GPU
offload, but a vulnerability in measured code could still expose its receipt
key. That would undermine the pre-decryption gate.

The verifier uses OpenSSL path validation, `cryptography` for ES384 verification,
bounded `cbor2` decoding and the pinned AWS root fingerprint. Application
bindings and policy are new code requiring independent review. It checks
certificate validity but does not fetch CRLs or implement an automated AWS
platform-revocation/advisory policy. Define an owner-managed patch and trusted
measurement withdrawal process before customer deployment.
[AWS evidence validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

Real EC2 end-to-end execution, lifecycle/failure testing, measured enclave
performance, independent protocol and BFV parameter review, and the existing
client private-key side-channel assurance work remain release requirements.
Host denial of service and traffic metadata remain visible. There is no claim
of general chosen-ciphertext security for the raw BFV encryption scheme.
