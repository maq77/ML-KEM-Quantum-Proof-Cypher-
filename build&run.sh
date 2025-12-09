#!/usr/bin/env bash

# -------------------------------------------------------
# Build libmlkem512.so and run the ML-KEM GUI on Linux
# -------------------------------------------------------

set -e

# Go to project root (directory of this script)
cd "$(dirname "$0")"

echo "============================================"
echo "  ML-KEM-512 Quantum-Safe Encryption Demo"
echo "  Build + Run (Linux)"
echo "============================================"
echo

# 1) Check for g++
if ! command -v g++ >/dev/null 2>&1; then
  echo "[ERROR] g++ not found. Install it, e.g. on Ubuntu:"
  echo "        sudo apt update && sudo apt install -y build-essential"
  exit 1
fi

# 2) Build libmlkem512.so
echo "[1/3] Building libmlkem512.so ..."

cd cpp

g++ -std=c++20 -O2 -fPIC \
  -I ./include \
  -I ./include/ml_kem \
  -I ./include/sha3 \
  -I ./include/subtle \
  -I ./include/randomshake \
  src/mlkem_512_c_api.cpp \
  -shared -o libmlkem512.so

echo "[INFO] Built: $(pwd)/libmlkem512.so"

cd ..

# 3) Check python3
echo
echo "[2/3] Checking python3 ..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Install Python 3.10+."
  exit 1
fi

# 4) Run GUI
echo
echo "[3/3] Starting ML-KEM GUI..."
echo

python3 main.py
