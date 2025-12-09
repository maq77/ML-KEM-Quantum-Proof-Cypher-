#!/usr/bin/env bash

# =====================================================
#  ML-KEM-512 Quantum-Safe Encryption Demo
#  Linux Bootstrap Script
#
#  - Detects package manager
#  - Installs g++ (and tools) if missing
#  - Builds libmlkem512.so from C++
#  - Runs python3 main.py
# =====================================================

set -e

# Go to project root (directory where this script lives)
cd "$(dirname "$0")"

echo "============================================"
echo "  ML-KEM-512 Quantum-Safe Encryption Demo"
echo "  Linux Bootstrap: install + build + run"
echo "============================================"
echo

# -------------------------------
# 1) Detect or install g++
# -------------------------------
if command -v g++ >/dev/null 2>&1; then
  echo "[INFO] g++ already installed."
else
  echo "[INFO] g++ not found. Trying to install it..."

  if command -v apt-get >/dev/null 2>&1; then
    echo "[INFO] Detected apt-based system (Ubuntu/Debian)."
    echo "       Installing build-essential (requires sudo)..."
    sudo apt-get update
    sudo apt-get install -y build-essential
  elif command -v apt >/dev/null 2>&1; then
    echo "[INFO] Detected apt (Ubuntu/Debian)."
    sudo apt update
    sudo apt install -y build-essential
  elif command -v dnf >/dev/null 2>&1; then
    echo "[INFO] Detected dnf (Fedora/RHEL)."
    sudo dnf install -y gcc-c++ make
  elif command -v yum >/dev/null 2>&1; then
    echo "[INFO] Detected yum (CentOS/RHEL)."
    sudo yum install -y gcc-c++ make
  elif command -v pacman >/dev/null 2>&1; then
    echo "[INFO] Detected pacman (Arch/Manjaro)."
    sudo pacman -Sy --needed base-devel
  elif command -v zypper >/dev/null 2>&1; then
    echo "[INFO] Detected zypper (openSUSE)."
    sudo zypper install -y gcc-c++ make
  elif command -v apk >/dev/null 2>&1; then
    echo "[INFO] Detected apk (Alpine)."
    sudo apk add build-base
  else
    echo "[ERROR] Could not detect a known package manager."
    echo "        Please install g++ manually and re-run this script."
    exit 1
  fi

  if ! command -v g++ >/dev/null 2>&1; then
    echo "[ERROR] g++ is still not available after installation."
    exit 1
  fi
fi

echo
echo "[OK] g++ is available."
g++ --version | head -n 1
echo

# -------------------------------
# 2) Build libmlkem512.so
# -------------------------------
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

# -------------------------------
# 3) Check python3
# -------------------------------
echo
echo "[2/3] Checking python3 ..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Please install Python 3.10+."
  echo "Example on Ubuntu:"
  echo "  sudo apt-get install -y python3 python3-tk"
  exit 1
fi

echo "[OK] python3 available:"
python3 --version
echo

# -------------------------------
# 4) Run GUI
# -------------------------------
echo "[3/3] Starting ML-KEM GUI..."
echo

python3 main.py
