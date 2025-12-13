import os
from typing import Optional, Tuple

from vendor.AES import AES


class AESWrapper:
    name = "AES (from-scratch)"
    modes = ("CTR", "CBC", "ECB")

    @staticmethod
    def key_len_bytes() -> int:
        return 32

    @staticmethod
    def iv_len_bytes(mode: str) -> int:
        return 16 if mode in ("CTR", "CBC") else 0

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, mode: str) -> Tuple[bytes, bytes]:
        """
        Returns: (ciphertext, iv_bytes)
        """
        mode = mode.upper()
        aes = AES(key)

        iv = b""
        if mode in ("CTR", "CBC"):
            iv = os.urandom(16)

        ct = aes.encrypt(plaintext, mode=mode, iv=(iv if iv else None))
        return ct, iv

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, mode: str, iv: bytes) -> bytes:
        mode = mode.upper()
        aes = AES(key)
        return aes.decrypt(ciphertext, mode=mode, iv=(iv if iv else None))
