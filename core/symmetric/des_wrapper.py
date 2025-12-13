import os
from typing import Tuple
from vendor.DES import des_encrypt, des_decrypt


class DESWrapper:
    name = "DES (legacy demo)"
    modes = ("ECB",)  

    @staticmethod
    def key_len_bytes() -> int:
        return 8

    @staticmethod
    def iv_len_bytes(mode: str) -> int:
        return 0

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, mode: str) -> Tuple[bytes, bytes]:
        mode = mode.upper()
        ct = des_encrypt(plaintext, key, mode=mode)
        return ct, b""

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, mode: str, iv: bytes) -> bytes:
        mode = mode.upper()
        return des_decrypt(ciphertext, key, mode=mode)
