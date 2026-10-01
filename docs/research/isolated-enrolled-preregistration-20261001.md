# E79 preregistration: isolated private enrollment and endpoint resources

Execute the independent R2-C1 task after E80/E78. Preserve E75/E76. Research
paths: `private_provision.py`, `isolated_enrolled.py`, scoped tests and
`benchmarks/isolated_enrolled_lab.py`. No production or deployed authentication
change. Local hostile-server separation is a protocol-data boundary, not
hostile same-user OS isolation or hardware attestation.

Use three spawned processes with different PIDs. Owner loads/discovers/encrypts
and enrolls the server by actual public TCP bytes. A new client acquires keys,
maps/positions/IDs, private checker seeds/fingerprints and private factory
coordinates in an AES-GCM envelope from the owner over another socket. The
64-byte owner key/context root is explicitly supplied through trusted local
IPC. Authenticate before bounded whitelisted decoding; never remote pickle or
dynamic imports. Fixed public-geometry padding for HE bootstrap is paid.
Every fresh mask answer and received query/response uses the existing full-Q
gate and evaluator. Bootstrap itself does not certify the unreviewed HE scheme.

Match strongest E76 global2048 geometry, real Mushroom/Semeion rows, held-out
queries64 onward and stable ties/IDs. Cache controls: raw acquisition/raw
retention, zlib1/raw, zlib9/raw, zlib1/compressed, zlib9/compressed. Include
already-owned local raw query controls without inventing client memory caps.
No queries/keys/private maps/checker material reach the compute server.

Record owner/server/client setup and query CPU, wall, current RSS/peak RSS,
post-import baselines, all framed application bytes, cold enrollment, new-client
bootstrap/acquisition+first query, and returning queries. Exclude neither
authenticated private setup nor fresh-answer upload. Process startup, interpreter
imports, TCP/TLS/WAN and resident-body distinctions are explicit. No shared
process/GIL resources are labeled endpoint measurements.

First run three independent-process pilot repetitions, at least five returning
queries each. Select the final process sample using pilot mean/variance and a
10% relative precision target, floor5/cap12. This is a pilot approximation,
not a guarantee. Use independent final observations and process-cluster
intervals; no p95 from tiny samples. Keep pilot/final raws separate and immutable.

Negative controls: tampered/stale/truncated private envelope rejects before
decoding or secret construction; wrong object types/counts/ranges; private
fields refused by server bootstrap; checker restore matches trusted source;
same full response verification-before-secret ordering. Full update/WAN/scale,
durable epoch and production/parameter/private-timing assurance remain separate.
Return to R6 after the finite panel, not after manufacturing a deployment win.
