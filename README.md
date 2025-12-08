# ML-KEM-512 Quantum-Safe GUI Demo

This project demonstrates a **post-quantum key encapsulation** scheme (ML-KEM-512)
implemented in **C++ from the FIPS-203-style `ml-kem` library**, wrapped in
Python via `ctypes`, with a **Tkinter GUI** that encrypts and decrypts files.

## Components

- `cpp/ml_kem/` – vendored C++ ML-KEM implementation (from https://github.com/itzmeanjan/ml-kem)
- `cpp/mlkem_512_c_api.cpp` – C API wrapper around ML-KEM-512 keygen/encaps/decaps
- `core/mlkem_ffi.py` – Python ctypes interface to the C API
- `core/stream_cipher.py` – simple stream cipher built from SHA-256 (educational)
- `core/key_store.py` – save/load ML-KEM-512 keypairs as hex JSON
- `gui/app.py` – Tkinter GUI for:
  - generating ML-KEM-512 keypairs
  - encrypting plaintext files (encapsulate + stream cipher)
  - decrypting cipher bundles (decapsulate + stream cipher)

## Build

```bash
cd cpp
make
cd ..
python main.py
