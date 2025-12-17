import hashlib

def verify(a: bytes, b: bytes) -> bool:
    return hashlib.sha256(a).digest() == hashlib.sha256(b).digest()
