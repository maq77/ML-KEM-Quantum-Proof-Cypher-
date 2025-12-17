import os
from core.symmetric.aes_wrapper import AES

def run(data: bytes):
    key = os.urandom(32)
    aes = AES(key)

    ct, iv = aes.encrypt(data)
    pt = aes.decrypt(ct, iv)

    return pt
