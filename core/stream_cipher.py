import hashlib


class SimpleStreamCipher:
    """
    Very simple stream cipher using SHA-256 as a PRG.

    This is NOT production-grade crypto. It is purely educational
    to demonstrate how to use the ML-KEM shared secret to encrypt
    arbitrary plaintext bytes.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        self.key = bytes(key)

    def _keystream(self, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hashlib.sha256(self.key + counter.to_bytes(4, "big")).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])

    def encrypt(self, plaintext: bytes) -> bytes:
        ks = self._keystream(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes) -> bytes:
        # XOR is symmetric
        return self.encrypt(ciphertext)
