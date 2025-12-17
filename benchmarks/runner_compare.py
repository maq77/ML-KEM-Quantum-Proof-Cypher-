import csv
import time
import os
import psutil
import hashlib
import numpy as np
from pathlib import Path

from core.mlkem_ffi import MLKEM512
from core.symmetric.aes_ctr_wrapper import AESCTR
from core.symmetric import kdf_sha256


RUNS = 30
WARMUP = 3

BASE = Path(__file__).resolve().parent
FILES = sorted(
    (BASE / "test_files").glob("file_*MB.bin"),
    key=lambda p: int(p.stem.split("_")[1].replace("MB", "")),
)

OUT = BASE / "results" / "compare_results.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)


def rss_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / (1024**2)


def sha(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def warmup(fn, *args):
    for _ in range(WARMUP):
        fn(*args)


# ---------------- SYSTEMS ---------------- #

def aes_only(data: bytes) -> bytes:
    key = os.urandom(32)
    aes = AESCTR(key)
    ct, iv = aes.encrypt(data)
    pt = aes.decrypt(ct, iv)
    return pt


def mlkem_only() -> bool:
    kem = MLKEM512()
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    ss2 = kem.decaps(ct, sk)
    return ss == ss2


def hybrid(data: bytes) -> bytes:
    kem = MLKEM512()
    pk, sk = kem.keygen()

    ct_kem, ss = kem.encaps(pk)
    key = kdf_sha256(ss, 32)

    aes = AESCTR(key)
    ct, iv = aes.encrypt(data)

    ss2 = kem.decaps(ct_kem, sk)
    key2 = kdf_sha256(ss2, 32)

    aes2 = AESCTR(key2)
    pt = aes2.decrypt(ct, iv)
    return pt


# ---------------- BENCH ---------------- #

def bench(fn, data=None):
    times, mem = [], []

    for _ in range(RUNS):
        m0 = rss_mb()
        t0 = time.perf_counter()

        out = fn(data) if data is not None else fn()

        t1 = time.perf_counter()
        m1 = rss_mb()

        times.append((t1 - t0) * 1000.0)
        mem.append(max(0.0, m1 - m0))

        if data is not None:
            if sha(out) != sha(data):
                raise RuntimeError("Correctness check failed (SHA-256 mismatch).")

    arr = np.array(times, dtype=np.float64)
    return {
        "mean_ms": float(arr.mean()),
        "std_ms": float(arr.std(ddof=1)) if RUNS > 1 else 0.0,
        "ci95_ms": float(1.96 * (arr.std(ddof=1) / np.sqrt(RUNS))) if RUNS > 1 else 0.0,
        "mem_mb": float(np.mean(mem)),
    }


def main():
    if not FILES:
        raise SystemExit(f"No files found in: {BASE / 'test_files'}")

    rows = []

    for f in FILES:
        data = f.read_bytes()
        size_mb = len(data) / (1024 * 1024)

        warmup(aes_only, data)
        warmup(hybrid, data)
        warmup(mlkem_only)

        r_aes = bench(aes_only, data)
        r_hyb = bench(hybrid, data)
        r_kem = bench(mlkem_only)

        rows += [
            {"system": "AES-CTR", "size_mb": size_mb, **r_aes},
            {"system": "Hybrid (ML-KEM + AES-CTR)", "size_mb": size_mb, **r_hyb},
            {"system": "ML-KEM (encaps/decaps)", "size_mb": size_mb, **r_kem},
        ]

        print(f"[OK] {f.name}: AES={r_aes['mean_ms']:.2f}ms | HYB={r_hyb['mean_ms']:.2f}ms | KEM={r_kem['mean_ms']:.2f}ms")

    with open(OUT, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    print(f"\n[OK] Comparison CSV saved: {OUT}")


if __name__ == "__main__":
    main()
