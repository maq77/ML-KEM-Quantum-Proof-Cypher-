import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes


class KeyStore:
    """
    Simple JSON-based key storage.
    Stores ML-KEM-512 public and secret keys as hex strings.
    """

    def save(self, path: str, keypair: KeyPair) -> None:
        data = {
            "scheme": "ML-KEM-512",
            "public_key_hex": keypair.public_key.hex(),
            "secret_key_hex": keypair.secret_key.hex(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str) -> KeyPair:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        pk = bytes.fromhex(data["public_key_hex"])
        sk = bytes.fromhex(data["secret_key_hex"])
        return KeyPair(public_key=pk, secret_key=sk)
