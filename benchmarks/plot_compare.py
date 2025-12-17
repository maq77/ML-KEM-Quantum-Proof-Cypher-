import csv
from pathlib import Path
import matplotlib.pyplot as plt
from collections import defaultdict

BASE = Path(__file__).resolve().parent
CSV = BASE / "results" / "compare_results.csv"
OUT = BASE / "results"
OUT.mkdir(exist_ok=True)

def read():
    with open(CSV, newline="") as f:
        return list(csv.DictReader(f))

def main():
    rows = read()
    data = defaultdict(lambda: defaultdict(list))

    for r in rows:
        size = float(r["size_mb"])
        sys = r["system"]
        data[sys]["size"].append(size)
        data[sys]["mean"].append(float(r["mean_ms"]))
        data[sys]["ci"].append(float(r["ci95_ms"]))

    plt.figure(figsize=(7,4))
    for sys, d in data.items():
        plt.errorbar(
            d["size"], d["mean"], yerr=d["ci"],
            marker="o", capsize=4, label=sys
        )

    plt.xlabel("File Size (MB)")
    plt.ylabel("Total Time (ms)")
    plt.title("Encryption Time Comparison")
    plt.grid(True)
    plt.legend()

    out = OUT / "fig_compare_systems.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    print("[OK]", out)

if __name__ == "__main__":
    main()
