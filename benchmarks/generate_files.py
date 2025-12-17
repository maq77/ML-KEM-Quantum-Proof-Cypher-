import os
from pathlib import Path

SIZES_MB = [1, 50, 500]
OUT_DIR = Path(__file__).resolve().parent / "test_files"


def make_file(path: Path, size_bytes: int, chunk_bytes: int = 8 * 1024 * 1024) -> None:
    """
    Creates a file of exact size_bytes using os.urandom in chunks
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size_bytes
    with open(path, "wb") as f:
        while remaining > 0:
            n = min(chunk_bytes, remaining)
            f.write(os.urandom(n))
            remaining -= n


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for mb in SIZES_MB:
        size_bytes = mb * 1024 * 1024
        p = OUT_DIR / f"file_{mb}MB.bin"
        if p.exists() and p.stat().st_size == size_bytes:
            print(f"[OK] Exists: {p.name} ({mb} MB)")
            continue
        print(f"[MAKE] {p.name} ({mb} MB)")
        make_file(p, size_bytes)
        print(f"[DONE] {p.name} -> {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
