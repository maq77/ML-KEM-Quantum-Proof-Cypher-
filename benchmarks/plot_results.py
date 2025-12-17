import csv
from pathlib import Path
from statistics import mean, stdev

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent
CSV_PATH = BASE_DIR / "results" / "benchmark_results.csv"
OUT_DIR = BASE_DIR / "results"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def read_rows(path: Path):
    with open(path, "r", encoding="utf-8") as fp:
        return list(csv.DictReader(fp))


def f(x):
    return float(x)


def mb(b):
    return b / (1024 * 1024)


def summarize(rows):
    groups = {}
    for r in rows:
        size = int(r["file_bytes"])
        groups.setdefault(size, []).append(r)

    summary = []
    for size in sorted(groups.keys()):
        rs = groups[size]

        enc = [f(r["total_enc_ms"]) for r in rs]
        kem = [f(r["kem_enc_ms"]) for r in rs]
        kdf = [f(r["kdf_ms"]) for r in rs]
        aes = [f(r["sym_enc_ms"]) for r in rs]

        def sd(x): return stdev(x) if len(x) > 1 else 0.0

        summary.append({
            "size_mb": mb(size),
            "enc_mean": mean(enc),
            "enc_sd": sd(enc),
            "kem_mean": mean(kem),
            "kdf_mean": mean(kdf),
            "aes_mean": mean(aes),
        })

    return summary


def plot_total_time(summary):
    x = [s["size_mb"] for s in summary]
    y = [s["enc_mean"] for s in summary]
    e = [s["enc_sd"] for s in summary]

    plt.figure(figsize=(6, 4))
    plt.errorbar(x, y, yerr=e, fmt="o-", capsize=4)
    plt.xlabel("File size (MB)")
    plt.ylabel("Total encryption time (ms)")
    plt.title("Hybrid Encryption Time vs File Size")
    plt.grid(True, alpha=0.3)

    out = OUT_DIR / "fig_total_time.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def plot_breakdown(summary):
    x = [s["size_mb"] for s in summary]
    kem = [s["kem_mean"] for s in summary]
    kdf = [s["kdf_mean"] for s in summary]
    aes = [s["aes_mean"] for s in summary]

    plt.figure(figsize=(6, 4))
    plt.bar(x, kem, label="ML-KEM")
    plt.bar(x, kdf, bottom=kem, label="KDF (SHA-256)")
    plt.bar(
        x,
        aes,
        bottom=[kem[i] + kdf[i] for i in range(len(x))],
        label="AES-256-CTR"
    )

    plt.xlabel("File size (MB)")
    plt.ylabel("Time (ms)")
    plt.title("Encryption Time Breakdown")
    plt.legend()
    plt.grid(True, axis="y", alpha=0.3)

    out = OUT_DIR / "fig_breakdown.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def plot_throughput(summary):
    x = [s["size_mb"] for s in summary]
    aes_ms = [s["aes_mean"] for s in summary]

    thr = [(x[i] / (aes_ms[i] / 1000)) for i in range(len(x))]

    plt.figure(figsize=(6, 4))
    plt.plot(x, thr, "o-")
    plt.xlabel("File size (MB)")
    plt.ylabel("Throughput (MB/s)")
    plt.title("AES-256-CTR Throughput")
    plt.grid(True, alpha=0.3)

    out = OUT_DIR / "fig_throughput.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def main():
    if not CSV_PATH.exists():
        raise SystemExit(f"Missing CSV: {CSV_PATH}")

    rows = read_rows(CSV_PATH)
    summary = summarize(rows)

    plot_total_time(summary)
    plot_breakdown(summary)
    plot_throughput(summary)

    print("\nSummary (mean values):")
    for s in summary:
        print(
            f"{s['size_mb']:>6.0f} MB | "
            f"total={s['enc_mean']:.3f} ms | "
            f"kem={s['kem_mean']:.3f} | "
            f"kdf={s['kdf_mean']:.3f} | "
            f"aes={s['aes_mean']:.3f}"
        )


if __name__ == "__main__":
    main()
