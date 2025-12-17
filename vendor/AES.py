from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


AESMode = Literal["ECB", "CBC", "CTR"]


def _require_len(name: str, b: bytes, n: int) -> None:
    if len(b) != n:
        raise ValueError(f"{name} must be {n} bytes, got {len(b)}")


def _require_one_of(name: str, v: str, allowed: tuple[str, ...]) -> str:
    v2 = v.upper()
    if v2 not in allowed:
        raise ValueError(f"{name} must be one of {allowed}, got {v!r}")
    return v2


@dataclass(frozen=True, slots=True)
class AES:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes (128/192/256-bit)")

    @property
    def key_size_bits(self) -> int:
        return len(self.key) * 8

    def encrypt(self, plaintext: bytes, mode: AESMode = "ECB", iv: Optional[bytes] = None) -> bytes:
        mode_u = _require_one_of("mode", mode, ("ECB", "CBC", "CTR"))

        if mode_u == "ECB":
            padder = PKCS7(128).padder()
            data = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.key), modes.ECB())
            enc = cipher.encryptor()
            return enc.update(data) + enc.finalize()

        if iv is None:
            raise ValueError(f"IV is required for {mode_u} mode")
        _require_len("iv", iv, 16)

        if mode_u == "CBC":
            padder = PKCS7(128).padder()
            data = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            enc = cipher.encryptor()
            return enc.update(data) + enc.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()

    def decrypt(self, ciphertext: bytes, mode: AESMode = "ECB", iv: Optional[bytes] = None) -> bytes:
        mode_u = _require_one_of("mode", mode, ("ECB", "CBC", "CTR"))

        if mode_u == "ECB":
            cipher = Cipher(algorithms.AES(self.key), modes.ECB())
            dec = cipher.decryptor()
            padded = dec.update(ciphertext) + dec.finalize()
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()

        if iv is None:
            raise ValueError(f"IV is required for {mode_u} mode")
        _require_len("iv", iv, 16)

        if mode_u == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            dec = cipher.decryptor()
            padded = dec.update(ciphertext) + dec.finalize()
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()
