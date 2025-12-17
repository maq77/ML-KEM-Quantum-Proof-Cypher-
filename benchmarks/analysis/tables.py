import csv
from pathlib import Path

CSV = Path("benchmarks/results/compare_results.csv")
OUT = Path("benchmarks/paper/tables.tex")
OUT.parent.mkdir(exist_ok=True)

rows = list(csv.DictReader(open(CSV)))

# write header
with OUT.open("w", encoding="utf-8") as f:
    f.write(r"""
\begin{table}[h]
\centering
\caption{Performance Comparison of Encryption Systems}
\begin{tabular}{lcccc}
\toprule
System & File Size (MB) & Mean (ms) & Std (ms) & 95\% CI (ms) \\
\midrule
""")

# append rows
with OUT.open("a", encoding="utf-8") as f:
    for r in rows:
        f.write(
            f"{r['system']} & {r['size_mb']} & "
            f"{float(r['mean_ms']):.2f} & "
            f"{float(r['std_ms']):.2f} & "
            f"{float(r['ci95_ms']):.2f} \\\\\n"
        )

# footer
with OUT.open("a", encoding="utf-8") as f:
    f.write(r"""
\bottomrule
\end{tabular}
\end{table}
""")

print("[OK] LaTeX table generated")
