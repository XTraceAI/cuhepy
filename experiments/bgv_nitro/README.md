# Experimental BGV Nitro evaluator

This is a separate CPU service for the homemade BGV research implementation.
Read [the threat model and limitations](../../docs/research/bgv-authentication.md)
before using it. It is not a production deployment. No BGV secret key or
plaintext index belongs in this service.

The client reuses the existing AWS evidence verifier and requires fresh
attestation of approved, nonzero PCR0/1/2 measurements. The receipt key is
generated inside the enclave, and signs only results that its fixed CPU circuit
computes. This service cannot endorse external GPU results.

## Build and local checks

From the repository root:

The owner environment needs the existing optional `bfv-nitro` dependency group
(also reused by BGV); the image installs its hash-pinned dependency lock.

```bash
make -C experiments/bfv_search_lab/_native PYTHON="$PWD/.venv/bin/python"
make -C experiments/bfv_search_lab/_owner PYTHON="$PWD/.venv/bin/python"
.venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_attested_bgv.py \
  experiments/bfv_search_lab/test_private_bgv.py \
  experiments/bfv_search_lab/test_bgv_nitro_service.py -q

docker build -f experiments/bgv_nitro/Dockerfile \
  -t cuhepy-bgv-nitro:research-local .
```

The image fixes BGVExecutionPolicy() in service.py: N16384, Q equal to the two
established 60-bit RNS primes, t1031, eta21, 512-dimensional vectors, public-key
index, 30-bit gadget decomposition, P25 and no optional c0 rounding. Policy is
not negotiated with the parent. To change these settings, change and review the
measured entrypoint, rebuild the image/EIF, and approve its new pins.

The setup byte cap is 384 MiB, independently of the maximum vector count.
An 8192-vector public index fits; a 32768-vector public index exceeds this
cap. Larger deployments need an explicitly reviewed resource profile/ingestion
protocol, not removal of the checks.

The image uses existing BFV pinned dependencies and AWS NSM build inputs. It
excludes host binaries, test files, keys and local data from the Docker context.
Only the public CPU extension is built into the image. The owner's separate
private extension stays on the owner machine.

On an AWS Nitro-capable build/deployment host, build an EIF from the image,
review its code/build inputs, obtain its measurements and provision those pins
to the owner through a trusted channel. Do not use debug mode, zero pins,
BFV image pins, a synthetic root, or measurements obtained solely from the
untrusted relay as a trust decision. The existing BFV deployment notes describe
the [AWS prerequisites](../../docs/research/native-bfv-nitro.md).

The service listens on enclave vsock port 5000. An untrusted byte relay can
forward it to the client; application framing uses distinct BGV magic XGN1.
The existing generic BFV TCP/vsock byte relay can be used without giving it any
signing or decryption key. Provision normal access control/transport privacy
for the relay separately.

## Owner flow

With local setup already generated using shallow_bgv.key_gen,
trace_bgv.evaluation_keys and the chosen encrypted index:

```python
from cuhepy.hamming.bfv_nitro import NitroAttestationPolicy
from experiments.bfv_search_lab.attested_bgv import BGVAttestedClient
from experiments.bfv_search_lab.security_bgv import BGVExecutionPolicy
from experiments.bgv_nitro.transport import NitroRemote

policy = BGVExecutionPolicy()
# approved_pcrs is a trusted {0: bytes48, 1: bytes48, 2: bytes48} configuration.
client = BGVAttestedClient(
    pk, sk, evaluation_keys, encrypted_index, vector_count,
    NitroAttestationPolicy(approved_pcrs), index_epoch=dataset_epoch, policy=policy,
)
remote = NitroRemote(host=relay_host, port=9000, policy=policy)
try:
    remote.register(client.registration_packet())
    client.accept_attestation(*remote.attest(client.begin_attestation()))
    response, receipt = remote.search(client.begin_query(binary_query))
    result = client.finish_query(response, receipt, k=3, all_distances=False)
    print(result.top)  # (owner's original vector position, exact Hamming distance)
finally:
    client.close()
```

The owner must retain the same ordered vector-to-document mapping. A registration
acknowledgement is not an attestation. Renew before the five-minute lease expires;
renewal cancels pending queries. Session state is intentionally not serializable,
and application epochs/revocation are managed outside this prototype.

Private terminal buffers must fit the owner's locked-memory limit. Missing
extension, unsupported ABI, lock failure and unauthenticated responses fail
closed. The raw OwnerClient remains a fixture, not a fallback for rejection.

## Private arithmetic checks

Standalone arithmetic/sanitizer tests:

```bash
g++ -std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/cuhepy/bfv/_cpu_ext experiments/bfv_search_lab/_owner/test_private.cpp \
  -lgmpxx -lgmp -pthread -o /tmp/bgv-private-check
/tmp/bgv-private-check
```

With Valgrind development headers installed, compile the same test using -O3,
-g and -DCUHEPY_BGV_CTGRIND. Run under
valgrind --tool=memcheck --error-exitcode=99. Repeat with GCC and Clang. Passing
the additional argument negative must produce exit code 99. A normal execution
must report zero errors. Some sandbox/ptrace environments require disabling
LeakSanitizer; Memcheck separately checks memory leaks. These tests do not
certify the whole client constant-time.

The paired performance experiment is explicitly **offline and synthetic**:

```bash
.venv/bin/python -m benchmarks.bgv_authentication --count 8192 --rounds 10 \
  --output /tmp/bgv-auth-baseline.json
.venv/bin/python -m benchmarks.bgv_authentication --count 8192 --rounds 10 \
  --rounded --output /tmp/bgv-auth-rounded.json
```
