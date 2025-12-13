import hashlib

def kdf_sha256(shared_secret: bytes, out_len: int) -> bytes:
    """
    Simple KDF for demo: SHA-256(ss || counter)
    """
    out = b""
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(shared_secret + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:out_len]
