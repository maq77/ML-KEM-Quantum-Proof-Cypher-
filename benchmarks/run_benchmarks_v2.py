import csv
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.mlkem_ffi import MLKEM512
from core.symmetric.registry import SYMMETRIC_ALGS
from core.symmetric import kdf_sha256


MODE = "CTR"
ALG_LABEL = "ML-KEM + AES-256 (CTR)"
TRIALS = 5
VERIFY_DECRYPT = True

REUSE_KEYPAIR = True
WARMUP_TRIALS = 1

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "test_files"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
OUT_CSV = RESULTS_DIR / "benchmark_results.csv"


def get_wrapper(alg_label: str):
    if alg_label not in SYMMETRIC_ALGS:
        raise ValueError(
            f"Algorithm '{alg_label}' not found in SYMMETRIC_ALGS.\n"
            f"Available: {list(SYMMETRIC_ALGS.keys())}"
        )
    _, _, Wrapper = SYMMETRIC_ALGS[alg_label]
    return Wrapper


def fmt_secs(seconds: float) -> str:
    s = max(0.0, seconds)
    if s < 60:
        return f"{s:.1f}s"
    m = int(s // 60)
    s2 = s - 60 * m
    if m < 60:
        return f"{m}m {s2:.0f}s"
    h = int(m // 60)
    m2 = m - 60 * h
    return f"{h}h {m2}m"


def fmt_rate(rate: float) -> str:
    if rate <= 0:
        return "0.00 t/s"
    return f"{rate:.2f} t/s"


def progress_line(done: int, total: int, start_t: float, extra: str = "") -> None:
    pct = (done / total) * 100.0 if total else 100.0
    elapsed = time.perf_counter() - start_t
    rate = (done / elapsed) if elapsed > 0 else 0.0
    eta = ((total - done) / rate) if rate > 0 else 0.0

    bar_len = 32
    filled = int(bar_len * pct / 100.0)
    bar = "█" * filled + "░" * (bar_len - filled)

    msg = (
        f"\r[{bar}] {pct:6.2f}%  ({done}/{total})  "
        f"elapsed={fmt_secs(elapsed)}  eta={fmt_secs(eta)}  {fmt_rate(rate)}  {extra}"
    )
    print(msg, end="", flush=True)


@dataclass(frozen=True)
class BenchResult:
    file_name: str
    file_bytes: int
    alg: str
    mode: str
    kem_enc_ms: float
    kdf_ms: float
    sym_enc_ms: float
    total_enc_ms: float
    kem_dec_ms: float
    sym_dec_ms: float
    total_dec_ms: float
    verify_ok: bool
    trial: int


def bench_one_file(
    kem: MLKEM512,
    Wrapper: Any,
    file_path: Path,
    mode: str,
    verify: bool,
    keypair: Optional[Tuple[bytes, bytes]] = None,
) -> Dict[str, Any]:
    plaintext = file_path.read_bytes()

    if keypair is None:
        pk, sk = kem.keygen()
    else:
        pk, sk = keypair

    t0 = time.perf_counter()

    t_kem0 = time.perf_counter()
    kem_ct, shared_secret = kem.encaps(pk)
    kem_enc_ms = (time.perf_counter() - t_kem0) * 1000.0

    t_kdf0 = time.perf_counter()
    sym_key = kdf_sha256(shared_secret, Wrapper.key_len_bytes())
    kdf_ms = (time.perf_counter() - t_kdf0) * 1000.0

    t_sym0 = time.perf_counter()
    sym_ct, iv = Wrapper.encrypt(sym_key, plaintext, mode=mode)
    sym_enc_ms = (time.perf_counter() - t_sym0) * 1000.0

    total_enc_ms = (time.perf_counter() - t0) * 1000.0

    kem_dec_ms = 0.0
    sym_dec_ms = 0.0
    total_dec_ms = 0.0
    ok = True

    if verify:
        t1 = time.perf_counter()

        t_kem1 = time.perf_counter()
        shared_secret2 = kem.decaps(kem_ct, sk)
        kem_dec_ms = (time.perf_counter() - t_kem1) * 1000.0

        sym_key2 = kdf_sha256(shared_secret2, Wrapper.key_len_bytes())

        t_sym1 = time.perf_counter()
        pt2 = Wrapper.decrypt(sym_key2, sym_ct, mode=mode, iv=iv)
        sym_dec_ms = (time.perf_counter() - t_sym1) * 1000.0

        total_dec_ms = (time.perf_counter() - t1) * 1000.0

        ok = (pt2 == plaintext)

    return {
        "file_name": file_path.name,
        "file_bytes": len(plaintext),
        "alg": ALG_LABEL,
        "mode": mode,
        "kem_enc_ms": kem_enc_ms,
        "kdf_ms": kdf_ms,
        "sym_enc_ms": sym_enc_ms,
        "total_enc_ms": total_enc_ms,
        "kem_dec_ms": kem_dec_ms,
        "sym_dec_ms": sym_dec_ms,
        "total_dec_ms": total_dec_ms,
        "verify_ok": ok,
    }


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
        fp.flush()
    tmp.replace(path)


def main() -> None:
    files = sorted(FILES_DIR.glob("file_*MB.bin"))
    if not files:
        raise SystemExit(
            f"No test files found in {FILES_DIR}.\n"
            f"Run: python -m benchmarks.generate_files"
        )

    kem = MLKEM512()
    Wrapper = get_wrapper(ALG_LABEL)

    keypair = None
    if REUSE_KEYPAIR:
        keypair = kem.keygen()

    if WARMUP_TRIALS > 0:
        warm_file = files[0]
        for _ in range(WARMUP_TRIALS):
            _ = bench_one_file(kem, Wrapper, warm_file, MODE, False, keypair=keypair)

    total_steps = len(files) * TRIALS
    done_steps = 0
    start_t = time.perf_counter()

    rows: List[Dict[str, Any]] = []

    for f in files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"\n=== Benchmark: {f.name} ({size_mb:.0f} MB) ===")

        for trial in range(1, TRIALS + 1):
            extra = f"| {f.name} T{trial}/{TRIALS}"
            progress_line(done_steps, total_steps, start_t, extra)

            r = bench_one_file(kem, Wrapper, f, MODE, VERIFY_DECRYPT, keypair=keypair)
            r["trial"] = trial
            rows.append(r)

            done_steps += 1
            progress_line(done_steps, total_steps, start_t, extra)
            print()

            print(
                f"Trial {trial}: enc_total={r['total_enc_ms']:.3f} ms "
                f"(kem={r['kem_enc_ms']:.3f}, kdf={r['kdf_ms']:.3f}, aes={r['sym_enc_ms']:.3f}) "
                f"verify={r['verify_ok']}"
            )
            if VERIFY_DECRYPT:
                print(
                    f"         dec_total={r['total_dec_ms']:.3f} ms "
                    f"(kem={r['kem_dec_ms']:.3f}, aes={r['sym_dec_ms']:.3f})"
                )

    write_csv(OUT_CSV, rows)
    print(f"\n[OK] Saved results to: {OUT_CSV}")


if __name__ == "__main__":
    main()
