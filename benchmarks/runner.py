import csv
import numpy as np
from metrics.timer import measure_time
from metrics.memory import get_rss_mb
from metrics.correctness import verify
from warmup import warmup

def benchmark(run_fn, data=None, runs=30):
    times, mem = [], []
    ok = True

    for _ in range(runs):
        before_mem = get_rss_mb()
        with measure_time() as t:
            out = run_fn(data) if data else run_fn()
        after_mem = get_rss_mb()

        times.append(t())
        mem.append(after_mem - before_mem)

        if data and not verify(data, out):
            ok = False

    return {
        "mean_ms": np.mean(times),
        "std_ms": np.std(times),
        "ci95_ms": 1.96 * np.std(times) / np.sqrt(len(times)),
        "mem_mb": np.mean(mem),
        "correct": ok
    }
