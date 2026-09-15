# Measured public BFV evaluator. Build from the repository root using this file.
# Immutable base images and a hash-checked AWS source archive bind build inputs;
# review/pin the resulting EIF PCRs. This is not a reproducible-build proof.
FROM rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS nsm
ADD --checksum=sha256:f78f9683ce02c857b944c84865ca2808f90f67a52605f120ac234095b1d03c35 https://codeload.github.com/aws/aws-nitro-enclaves-nsm-api/tar.gz/1993eeb0620d35f5cefc50b17638b432325328f9 /tmp/nsm.tar.gz
WORKDIR /build/nsm
RUN tar -xzf /tmp/nsm.tar.gz --strip-components=1
COPY experiments/bfv_nitro/nsmlib.Cargo.lock ./Cargo.lock
RUN cargo build --release --locked -p nsm-lib

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS arithmetic
RUN apt-get update && apt-get install -y --no-install-recommends g++ make libgmp-dev && rm -rf /var/lib/apt/lists/*
COPY src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext /build/bfv_cpu_ext
RUN make -C /build/bfv_cpu_ext "_bfv_rns$(python -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')" CXXFLAGS='-O3 -fstack-protector-strong -D_FORTIFY_SOURCE=3' LDFLAGS='-Wl,-z,relro,-z,now,-z,noexecstack'

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
RUN apt-get update && apt-get install -y --no-install-recommends libgmp10 libgmpxx4ldbl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY experiments/bfv_nitro/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock
COPY src/xtrace_sdk /app/src/xtrace_sdk
COPY experiments/bfv_nitro/__init__.py experiments/bfv_nitro/transport.py experiments/bfv_nitro/service.py /app/experiments/bfv_nitro/
COPY --from=arithmetic /build/bfv_cpu_ext/_bfv_rns*.so /app/src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/
COPY --from=nsm /build/nsm/target/release/libnsm.so /usr/local/lib/libnsm.so
COPY --from=nsm /build/nsm/LICENSE /build/nsm/NOTICE /usr/local/share/licenses/aws-nsm/
COPY LICENSE /usr/local/share/licenses/xtrace-sdk/LICENSE
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Check imports/ABI during the build; the NSM device is available only at runtime.
RUN python -c 'from xtrace_sdk.x_vec.crypto.bfv_cpu_ext import _bfv_rns; assert _bfv_rns.ABI_VERSION == 4; from experiments.bfv_nitro.service import EnclaveApplication'
ENTRYPOINT ["python", "-m", "experiments.bfv_nitro.service"]
