from .aes_wrapper import AESWrapper
from .des_wrapper import DESWrapper


SYMMETRIC_ALGS = {
    "ML-KEM + AES-256 (CTR)": ("AES", "CTR", AESWrapper),
    "ML-KEM + AES-256 (CBC)": ("AES", "CBC", AESWrapper),
    "ML-KEM + AES-256 (ECB)": ("AES", "ECB", AESWrapper),
    "ML-KEM + DES (ECB)": ("DES", "ECB", DESWrapper),
}
