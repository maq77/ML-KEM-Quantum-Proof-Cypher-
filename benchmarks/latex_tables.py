import csv
from pathlib import Path
from collections import defaultdict

BASE = Path(__file__).resolve().parent
CSV = BASE / "results" / "compare_results.csv"
OUT = BASE / "paper" / "tables.tex"
OUT.parent.mkdir(exist_ok=True)

def main():
    rows = list(csv.DictReader(open(CSV)))
    groups = defaultdict(list)

    for r in rows:
        key = (r["system"], r["size_mb"])
        groups[key].append(r)

    with open(OUT, "w") as f:
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Encryption Performance Comparison}\n")
        f.write("\\begin{tabular}{lccc}\n")
        f.write("\\hline\n")
        f.write("System & Size (MB) & Time (ms) & CI$_{95\\%}$ \\\\\n")
        f.write("\\hline\n")

        for (sys, size), rs in sorted(groups.items()):
            r = rs[0]
            f.write(
                f"{sys} & {size} & "
                f"{float(r['mean_ms']):.2f} & "
                f"$\\pm${float(r['ci95_ms']):.2f} \\\\\n"
            )

        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print("[OK] LaTeX table generated:", OUT)

if __name__ == "__main__":
    main()
