from core.mlkem_ffi import MLKEM512

def run():
    kem = MLKEM512()
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    ss2 = kem.decaps(ct, sk)
    return ss == ss2
