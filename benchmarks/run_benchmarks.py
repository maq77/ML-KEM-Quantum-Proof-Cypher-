import csv
import time
from pathlib import Path

from core.mlkem_ffi import MLKEM512
from core.symmetric.registry import SYMMETRIC_ALGS
from core.symmetric import kdf_sha256


# ---- Config ----
MODE = "CTR"                           # Symmetric encryption mode
ALG_LABEL = "ML-KEM + AES-256 (CTR)"   # Algorithm to benchmark
TRIALS = 5                             # Number of trials per file
VERIFY_DECRYPT = True                  # Verify decryption correctness
# ----------------

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


def bench_one_file(kem: MLKEM512, Wrapper, file_path: Path):
    plaintext = file_path.read_bytes()

    # (A) ML-KEM keygen is not per-file in real systems, but you can measure it once too if you want.
    # Here we assume you already have a keypair for encaps/decaps.
    # We'll generate per run to keep benchmark self-contained:
    pk, sk = kem.keygen()

    # --- Encrypt ---
    t0 = time.perf_counter()

    t_kem0 = time.perf_counter()
    kem_ct, shared_secret = kem.encaps(pk)
    kem_enc_ms = (time.perf_counter() - t_kem0) * 1000.0

    t_kdf0 = time.perf_counter()
    sym_key = kdf_sha256(shared_secret, Wrapper.key_len_bytes())
    kdf_ms = (time.perf_counter() - t_kdf0) * 1000.0

    t_sym0 = time.perf_counter()
    sym_ct, iv = Wrapper.encrypt(sym_key, plaintext, mode=MODE)
    sym_enc_ms = (time.perf_counter() - t_sym0) * 1000.0

    total_enc_ms = (time.perf_counter() - t0) * 1000.0

    # --- Decrypt (optional) ---
    kem_dec_ms = 0.0
    sym_dec_ms = 0.0
    total_dec_ms = 0.0
    ok = True

    if VERIFY_DECRYPT:
        t1 = time.perf_counter()

        t_kem1 = time.perf_counter()
        shared_secret2 = kem.decaps(kem_ct, sk)
        kem_dec_ms = (time.perf_counter() - t_kem1) * 1000.0

        t_kdf1 = time.perf_counter()
        sym_key2 = kdf_sha256(shared_secret2, Wrapper.key_len_bytes())
        _ = sym_key2
        # kdf time usually tiny; we can reuse kdf_ms or measure again if you want:
        # kdf_dec_ms = (time.perf_counter() - t_kdf1) * 1000.0
        _ = (time.perf_counter() - t_kdf1)

        t_sym1 = time.perf_counter()
        pt2 = Wrapper.decrypt(sym_key2, sym_ct, mode=MODE, iv=iv)
        sym_dec_ms = (time.perf_counter() - t_sym1) * 1000.0

        total_dec_ms = (time.perf_counter() - t1) * 1000.0

        ok = (pt2 == plaintext)

    return {
        "file_name": file_path.name,
        "file_bytes": len(plaintext),
        "alg": ALG_LABEL,
        "mode": MODE,
        "kem_enc_ms": kem_enc_ms,
        "kdf_ms": kdf_ms,
        "sym_enc_ms": sym_enc_ms,
        "total_enc_ms": total_enc_ms,
        "kem_dec_ms": kem_dec_ms,
        "sym_dec_ms": sym_dec_ms,
        "total_dec_ms": total_dec_ms,
        "verify_ok": ok,
    }


def main():
    files = sorted(FILES_DIR.glob("file_*MB.bin"))
    if not files:
        raise SystemExit(
            f"No test files found in {FILES_DIR}.\n"
            f"Run: python benchmarks/generate_files.py"
        )

    kem = MLKEM512()
    Wrapper = get_wrapper(ALG_LABEL)

    rows = []
    for f in files:
        print(f"\n=== Benchmark: {f.name} ({f.stat().st_size / (1024*1024):.0f} MB) ===")
        for trial in range(1, TRIALS + 1):
            r = bench_one_file(kem, Wrapper, f)
            r["trial"] = trial
            rows.append(r)

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

    # Write CSV
    fieldnames = list(rows[0].keys())
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"\n[OK] Saved results to: {OUT_CSV}")


if __name__ == "__main__":
    main()
