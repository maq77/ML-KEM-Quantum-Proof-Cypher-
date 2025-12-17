import csv
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import os

from core.mlkem_ffi import MLKEM512
from core.symmetric.registry import SYMMETRIC_ALGS
from core.symmetric import kdf_sha256


# ===================== CONFIG =====================

MODE = "CTR"
ALG_LABEL = "ML-KEM + AES-256 (CTR)"

TRIALS = 30
WARMUP_TRIALS = 3
VERIFY_DECRYPT = True
REUSE_KEYPAIR = True

# ==================================================

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "test_files"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

OUT_CSV = RESULTS_DIR / "benchmark_results.csv"


# ===================== HELPERS =====================

def get_wrapper(alg_label: str):
    if alg_label not in SYMMETRIC_ALGS:
        raise ValueError(f"Algorithm '{alg_label}' not found.")
    _, _, Wrapper = SYMMETRIC_ALGS[alg_label]
    return Wrapper


def rss_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2)


def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def fmt_secs(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds // 60)
    s = int(seconds - m * 60)
    return f"{m}m {s}s"


def progress(done: int, total: int, start: float, tag: str = ""):
    pct = (done / total) * 100
    elapsed = time.perf_counter() - start
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0

    bar_len = 32
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)

    print(
        f"\r[{bar}] {pct:6.2f}% ({done}/{total}) "
        f"elapsed={fmt_secs(elapsed)} eta={fmt_secs(eta)} "
        f"{rate:.2f} t/s {tag}",
        end="",
        flush=True,
    )


# ===================== RESULT MODEL =====================

@dataclass
class BenchRow:
    file_name: str
    file_bytes: int
    trial: int

    kem_enc_ms: float
    kem_dec_ms: float
    kdf_ms: float

    aes_enc_ms: float
    aes_dec_ms: float

    total_enc_ms: float
    total_dec_ms: float

    mem_peak_mb: float
    correct: bool


# ===================== CORE BENCH =====================

def bench_once(
    kem: MLKEM512,
    Wrapper: Any,
    plaintext: bytes,
    keypair: Optional[Tuple[bytes, bytes]],
) -> BenchRow:

    before_mem = rss_mb()

    if keypair is None:
        pk, sk = kem.keygen()
    else:
        pk, sk = keypair

    t0 = time.perf_counter()

    t = time.perf_counter()
    kem_ct, ss = kem.encaps(pk)
    kem_enc_ms = (time.perf_counter() - t) * 1000

    t = time.perf_counter()
    key = kdf_sha256(ss, Wrapper.key_len_bytes())
    kdf_ms = (time.perf_counter() - t) * 1000

    t = time.perf_counter()
    ct, iv = Wrapper.encrypt(key, plaintext, mode=MODE)
    aes_enc_ms = (time.perf_counter() - t) * 1000

    total_enc_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()

    t = time.perf_counter()
    ss2 = kem.decaps(kem_ct, sk)
    kem_dec_ms = (time.perf_counter() - t) * 1000

    key2 = kdf_sha256(ss2, Wrapper.key_len_bytes())

    t = time.perf_counter()
    pt = Wrapper.decrypt(key2, ct, mode=MODE, iv=iv)
    aes_dec_ms = (time.perf_counter() - t) * 1000

    total_dec_ms = (time.perf_counter() - t1) * 1000

    after_mem = rss_mb()

    return BenchRow(
        file_name="",
        file_bytes=len(plaintext),
        trial=0,
        kem_enc_ms=kem_enc_ms,
        kem_dec_ms=kem_dec_ms,
        kdf_ms=kdf_ms,
        aes_enc_ms=aes_enc_ms,
        aes_dec_ms=aes_dec_ms,
        total_enc_ms=total_enc_ms,
        total_dec_ms=total_dec_ms,
        mem_peak_mb=max(0.0, after_mem - before_mem),
        correct=(sha256(plaintext) == sha256(pt)),
    )


# ===================== MAIN =====================

def main():
    files = sorted(
        FILES_DIR.glob("file_*MB.bin"),
        key=lambda p: int(p.stem.split("_")[1].replace("MB", "")),
    )

    if not files:
        raise SystemExit("No test files found.")

    kem = MLKEM512()
    Wrapper = get_wrapper(ALG_LABEL)

    keypair = kem.keygen() if REUSE_KEYPAIR else None

    # ---------- Warmup ----------
    for _ in range(WARMUP_TRIALS):
        _ = bench_once(kem, Wrapper, files[0].read_bytes(), keypair)

    rows: List[Dict[str, Any]] = []

    total = len(files) * TRIALS
    done = 0
    start = time.perf_counter()

    for f in files:
        data = f.read_bytes()
        size_mb = len(data) / (1024 * 1024)
        print(f"\n=== {f.name} ({size_mb:.0f} MB) ===")

        for trial in range(1, TRIALS + 1):
            progress(done, total, start, f"{f.name} T{trial}/{TRIALS}")

            r = bench_once(kem, Wrapper, data, keypair)
            r.file_name = f.name
            r.trial = trial

            rows.append(r.__dict__)

            done += 1
            progress(done, total, start, f"{f.name} T{trial}/{TRIALS}")
            print()

            print(
                f"enc={r.total_enc_ms:.3f} ms "
                f"(aes={r.aes_enc_ms:.3f}, kem={r.kem_enc_ms:.3f}) "
                f"dec={r.total_dec_ms:.3f} ms "
                f"mem={r.mem_peak_mb:.2f} MB ok={r.correct}"
            )

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    print(f"\n[OK] Results saved to {OUT_CSV}")


if __name__ == "__main__":
    main()
