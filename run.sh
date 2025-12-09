#!/usr/bin/env bash

# -------------------------------------------------------
# Run ML-KEM GUI on Linux (no build, expects libmlkem512.so)
# -------------------------------------------------------

set -e

cd "$(dirname "$0")"

echo "============================================"
echo "  ML-KEM-512 Quantum-Safe Encryption Demo"
echo "  Run Only (Linux)"
echo "============================================"
echo

# Check library
if [ ! -f "cpp/libmlkem512.so" ]; then
  echo "[ERROR] cpp/libmlkem512.so not found."
  echo "Please run ./build_and_run_mlkem.sh once to build it."
  exit 1
fi

# Check python3
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Install Python 3.10+."
  exit 1
fi

echo "[INFO] Starting ML-KEM GUI..."
echo

python3 main.py
