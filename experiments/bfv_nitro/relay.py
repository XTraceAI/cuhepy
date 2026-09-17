"""Untrusted, bounded TCP-to-vsock relay for the Nitro BFV experiment.

Bind localhost by default and reach it through an authenticated SSH tunnel or a
deployment-managed TLS endpoint. This process has no BFV or signing secret and
cannot create accepted results. It can observe traffic and deny service.
"""

import argparse
import select
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def relay(stream, cid, port, admission):
    """Relay one RPC with bounded buffers and a five-minute connection lifetime."""
    try:
        with stream, socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as enclave:
            enclave.settimeout(60)
            enclave.connect((cid, port))
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                readable, _, _ = select.select(
                    [stream, enclave], [], [], min(60, deadline - time.monotonic())
                )
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = enclave if source is stream else stream
                    target.settimeout(60)
                    target.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        admission.release()


def main():
    """Expose a selected enclave CID without accepting unbounded worker queues."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cid", type=int, required=True)
    parser.add_argument("--enclave-port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    if args.cid < 3 or not 1 <= args.port <= 65535 or not 1 <= args.enclave_port <= 65535:
        parser.error("Use a valid enclave CID and TCP/vsock ports")
    admission = threading.BoundedSemaphore(4)
    with (
        socket.create_server((args.host, args.port), backlog=4) as listener,
        ThreadPoolExecutor(max_workers=4) as workers,
    ):
        while True:
            stream, _ = listener.accept()
            if admission.acquire(blocking=False):
                workers.submit(relay, stream, args.cid, args.enclave_port, admission)
            else:
                stream.close()


if __name__ == "__main__":
    main()
