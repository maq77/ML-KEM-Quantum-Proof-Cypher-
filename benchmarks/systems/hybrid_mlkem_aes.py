from core.mlkem_ffi import MLKEM512
from core.symmetric.aes_wrapper import AES
from core.symmetric import kdf_sha256

def run(data: bytes):
    kem = MLKEM512()
    pk, sk = kem.keygen()

    kem_ct, ss = kem.encaps(pk)
    key = kdf_sha256(ss, 32)

    aes = AES(key)
    ct, iv = aes.encrypt(data)

    ss2 = kem.decaps(kem_ct, sk)
    key2 = kdf_sha256(ss2, 32)
    aes2 = AES(key2)

    pt = aes2.decrypt(ct, iv)
    return pt
