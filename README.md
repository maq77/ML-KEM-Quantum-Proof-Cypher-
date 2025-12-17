# 🛡️ ML-KEM-512 Quantum-Safe Encryption GUI

**Post-Quantum Cryptography Demo using C++ Core + Python GUI**


## 📌 Overview

This project is a **full educational implementation and GUI demonstration of NIST-standardized Post-Quantum Cryptography using ML-KEM-512 (Kyber)**.

It consists of:

* ✅ **Native C++ ML-KEM-512 core** (high-performance)
* ✅ **Python FFI (ctypes) bridge**
* ✅ **Tkinter graphical interface**
* ✅ **End-to-end encryption & decryption workflow**
* ✅ **Cross-platform (Windows & Linux)**
* ✅ **Automated build & run scripts**
* ✅ **Educational stream cipher for message encryption**

This project demonstrates **how modern quantum-safe key exchange works in real systems**, similar to what is used by:

* TLS 1.3 with PQC
* Secure messaging systems
* Government-grade cryptographic protocols

---

## 🔐 Cryptographic Design

This system performs **hybrid encryption**:

1. **ML-KEM-512 (Post-Quantum Key Encapsulation)**

   * Generates a **quantum-secure shared secret**
   * Resistant to **Shor’s algorithm** and quantum attacks

2. **SimpleStreamCipher (Educational)**

   * Uses SHA-256 to generate a keystream
   * Encrypts arbitrary files using XOR
   * Demonstrates **real-world hybrid encryption design**

Final encrypted bundle contains:

```json
{
  "scheme": "ML-KEM-512 + SimpleStreamCipher",
  "ciphertext_mlkem_hex": "...",
  "stream_ciphertext_hex": "..."
}
```

---

## 📂 Project Structure

```
ML-KEM/
│
├── cpp/                    # Native C++ cryptography core
│   ├── include/
│   ├── src/
│   ├── mlkem512.dll        # Windows compiled library
│   └── libmlkem512.so      # Linux compiled library
│
├── core/                   # Python cryptography layer
│   ├── mlkem_ffi.py
│   ├── stream_cipher.py
│   └── key_store.py
│
├── gui/                    # GUI application
│   └── app.py
│
├── main.py                 # Application entry point
├── requirements.txt
├── README.md
├── run_mlkem_gui.bat       # Windows run script
├── bootstrap_linux.sh      # Linux auto-install + build + run
└── run_mlkem_gui_linux.sh  # Linux run-only
```

---

## ⚙️ System Requirements

### ✅ Windows

* Windows 10 or newer
* Python **3.10+**
* C++ DLL already provided: `mlkem512.dll`

### ✅ Linux

* Python **3.10+**
* `g++` compiler (installed automatically via script)
* `tkinter` (usually included with Python)

---

## 📦 Python Dependencies

`requirements.txt`

```txt
# Only built-in Python libraries are used
# No external packages required
```

No external pip packages are needed.

---

## ▶️ How to Run on Windows (No Build Required)

1. Ensure Python is installed:

```cmd
python --version
```

2. Run directly:

```cmd
python main.py
```

OR double-click:

```
run_mlkem_gui.bat
```

The GUI will start immediately.

---

## ▶️ How to Run on Linux (Fully Automated)

### ✅ First-Time Run (Auto-Install + Build + Run)

```bash
chmod +x bootstrap_linux.sh
./bootstrap_linux.sh
```

This will automatically:

1. Install `g++`
2. Build `libmlkem512.so`
3. Launch the GUI

---

### ✅ After First Build (Run Only)

```bash
chmod +x run_mlkem_gui_linux.sh
./run_mlkem_gui_linux.sh
```

---

## 🔑 GUI Features

| Feature              | Description                             |
| -------------------- | --------------------------------------- |
| Key Pair Generation  | Quantum-safe public & secret keys       |
| Key Saving & Loading | Secure JSON storage                     |
| File Encryption      | Hybrid quantum-safe encryption          |
| File Decryption      | Full recovery of plaintext              |
| Animated Story Panel | Step-by-step cryptography visualization |
| Performance Timing   | Real-time benchmark display             |
| Error Handling       | Friendly validation messages            |

---

## 🔬 Educational Crypto Visualization

The GUI **animates the cryptographic flow**:

* lattice vector creation
* noise injection
* polynomial compression
* shared-secret derivation
* stream cipher encryption
* decapsulation verification

This makes the system **ideal for academic demonstrations and exams**.

---

## 📜 Academic Standards

This project is based on:

* ✅ **NIST FIPS-203 (ML-KEM / Kyber)**
* ✅ **Post-Quantum Cryptography migration models**
* ✅ **Real-world hybrid encryption architecture**
* ✅ **Industry-grade C++ cryptographic performance**
* ✅ **Python FFI integration**

---

## 🛠 Troubleshooting

### ❌ `g++: not found` (Linux)

Run:

```bash
sudo apt install build-essential
```

Or simply:

```bash
./bootstrap_linux.sh
```

---

### ❌ `mlkem512.dll not found`

Make sure:

```
ML-KEM/cpp/mlkem512.dll
```

exists near `main.py`.

---

### ❌ `python3-tk not installed`

Install:

```bash
sudo apt install python3-tk
```

---

## 🧪 Verification

The system automatically validates:

* Encapsulation success
* Shared-secret integrity
* Decryption accuracy
* Key length correctness

All failures produce **safe GUI alerts**.

---

## 🚀 Learning Outcomes

By studying this project, you gain:

✅ Understanding of **Post-Quantum Cryptography**
✅ Knowledge of **hybrid encryption systems**
✅ Experience with **C++ ↔ Python FFI**
✅ Secure **cryptographic software architecture design**
✅ Cross-platform deployment practices

---

## 🏁 Conclusion

This project represents a **full quantum-safe encryption workflow using real NIST-standard algorithms**, implemented in a professional, modular, and cross-platform manner suitable for:

* University projects
* Crypto practical exams
* Research demonstrations
* Security presentations

---

If you want, I can also provide:

✅ A **1-page theoretical PDF explanation for your report**
✅ A **presentation PowerPoint for your defense**
✅ A **diagram of ML-KEM internals for academic submission**

Just tell me 👍

