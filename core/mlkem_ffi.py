import ctypes
import os
from pathlib import Path


def _load_library():
    here = Path(__file__).resolve().parent
    cpp_dir = here.parent / "cpp"

    if os.name == "nt":
        # Ensure MinGW runtime DLLs are visible
        mingw_bin = Path(r"C:\mingw64\bin")
        if mingw_bin.exists():
            os.add_dll_directory(str(mingw_bin))
        lib_name = "mlkem512.dll"
    else:
        lib_name = "libmlkem512.so"

    lib_path = cpp_dir / lib_name
    if not lib_path.exists():
        raise FileNotFoundError(f"ML-KEM library not found at {lib_path}")
    return ctypes.CDLL(str(lib_path))


_lib = _load_library()

# Query lengths from C
_lib.mlkem_512_pkey_len.restype = ctypes.c_size_t
_lib.mlkem_512_skey_len.restype = ctypes.c_size_t
_lib.mlkem_512_cipher_len.restype = ctypes.c_size_t
_lib.mlkem_512_shared_secret_len.restype = ctypes.c_size_t

PKEY_LEN = _lib.mlkem_512_pkey_len()
SKEY_LEN = _lib.mlkem_512_skey_len()
CT_LEN   = _lib.mlkem_512_cipher_len()
SS_LEN   = _lib.mlkem_512_shared_secret_len()

# Function prototypes
_lib.mlkem_512_keygen.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
_lib.mlkem_512_keygen.restype = ctypes.c_int

_lib.mlkem_512_encaps.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),   # pk_in
    ctypes.POINTER(ctypes.c_uint8),   # ct_out
    ctypes.POINTER(ctypes.c_uint8),   # ss_out
]
_lib.mlkem_512_encaps.restype = ctypes.c_int

_lib.mlkem_512_decaps.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),   # sk_in
    ctypes.POINTER(ctypes.c_uint8),   # ct_in
    ctypes.POINTER(ctypes.c_uint8),   # ss_out
]
_lib.mlkem_512_decaps.restype = ctypes.c_int


class MLKEM512:
    """
    Python wrapper around ML-KEM-512 C++ implementation.

    Methods:
      - keygen() -> (pk, sk)
      - encaps(pk=None) -> (ct, ss)
      - decaps(ct, sk=None) -> ss
    """

    def __init__(self):
        self.pk = None
        self.sk = None

    def keygen(self):
        pk_buf = (ctypes.c_ubyte * PKEY_LEN)()
        sk_buf = (ctypes.c_ubyte * SKEY_LEN)()

        rc = _lib.mlkem_512_keygen(pk_buf, sk_buf)
        if rc != 0:
            raise RuntimeError("mlkem_512_keygen failed")

        self.pk = bytes(pk_buf)
        self.sk = bytes(sk_buf)
        return self.pk, self.sk

    def encaps(self, pk=None):
        if pk is None:
            if self.pk is None:
                raise ValueError("No public key; call keygen() or pass pk explicitly")
            pk = self.pk

        if len(pk) != PKEY_LEN:
            raise ValueError(f"Invalid public key length (expected {PKEY_LEN})")

        pk_buf = (ctypes.c_ubyte * PKEY_LEN).from_buffer_copy(pk)
        ct_buf = (ctypes.c_ubyte * CT_LEN)()
        ss_buf = (ctypes.c_ubyte * SS_LEN)()

        rc = _lib.mlkem_512_encaps(pk_buf, ct_buf, ss_buf)
        if rc != 0:
            raise RuntimeError("mlkem_512_encaps failed (malformed public key?)")

        return bytes(ct_buf), bytes(ss_buf)

    def decaps(self, ct, sk=None):
        if sk is None:
            if self.sk is None:
                raise ValueError("No secret key; call keygen() or pass sk explicitly")
            sk = self.sk

        if len(sk) != SKEY_LEN:
            raise ValueError(f"Invalid secret key length (expected {SKEY_LEN})")
        if len(ct) != CT_LEN:
            raise ValueError(f"Invalid ciphertext length (expected {CT_LEN})")

        sk_buf = (ctypes.c_ubyte * SKEY_LEN).from_buffer_copy(sk)
        ct_buf = (ctypes.c_ubyte * CT_LEN).from_buffer_copy(ct)
        ss_buf = (ctypes.c_ubyte * SS_LEN)()

        rc = _lib.mlkem_512_decaps(sk_buf, ct_buf, ss_buf)
        if rc != 0:
            raise RuntimeError("mlkem_512_decaps failed")

        return bytes(ss_buf)
