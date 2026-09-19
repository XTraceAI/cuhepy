ABI_VERSION: int

def available() -> bool: ...
def create_server(
    relin: object, keys: tuple[tuple[int, object], ...], padded: int, t: int, target_hex: str
) -> object: ...
def packed_search(
    server: object,
    query: tuple[bytes, bytes],
    index: tuple[tuple[bytes, bytes], ...],
    count: int,
    compact: bool,
) -> list[tuple[bytes, bytes]]: ...
def server_bytes(server: object) -> int: ...
