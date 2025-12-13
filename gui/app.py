import os
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.mlkem_ffi import MLKEM512
from core.stream_cipher import SimpleStreamCipher
from core.key_store import KeyStore, KeyPair
from core.symmetric.registry import SYMMETRIC_ALGS
from core.symmetric import kdf_sha256


class MLKEMGuiApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ML-KEM-512 Quantum-Safe Encryption Demo")

        # Crypto engine & key storage
        self.kem = MLKEM512()
        self.keystore = KeyStore()
        self.keypair: KeyPair | None = None

        # UI state variables
        self.keyfile_var = tk.StringVar()
        self.plain_in_var = tk.StringVar()
        self.bundle_out_var = tk.StringVar()
        self.bundle_in_var = tk.StringVar()
        self.plain_out_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")

        # Cipher scheme selection (only ML-KEM implemented)
        self.cipher_var = tk.StringVar(
            value="ML-KEM-512 + AES/DES (Quantum-safe)"
        )

        self._build_ui()

    # -------------------------------------------------------------------------
    # UI construction
    # -------------------------------------------------------------------------
    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")

        # Title
        title = ttk.Label(
            main,
            text="ML-KEM-512(Key Gen) + AES/DES\n(C++ quantum-safe core + Python GUI)",
            font=("Segoe UI", 12, "bold"),
        )
        title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        # Cipher scheme dropdown
        ttk.Label(main, text="Cipher scheme:", font=("Segoe UI", 10, "bold")).grid(
            row=1, column=0, sticky="w"
        )
        cipher_box = ttk.Combobox(
            main,
            textvariable=self.cipher_var,
            values=list(SYMMETRIC_ALGS.keys()),
            state="readonly",
        )
        cipher_box.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(0, 5))
        cipher_box.current(0)

        # --- Keypair section ---
        ttk.Label(main, text="Keypair:", font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(5, 0)
        )

        ttk.Button(
            main, text="1) Generate new ML-KEM-512 keypair", command=self.on_keygen
        ).grid(row=3, column=0, sticky="w", pady=(2, 2))

        ttk.Button(
            main, text="2) Save keypair...", command=self.on_save_keypair
        ).grid(row=3, column=1, sticky="w", padx=(5, 0))

        ttk.Button(
            main, text="3) Load keypair...", command=self.on_load_keypair
        ).grid(row=3, column=2, sticky="w", padx=(5, 0))

        ttk.Entry(main, textvariable=self.keyfile_var, width=40).grid(
            row=3, column=3, sticky="ew", padx=(5, 0)
        )

        self.key_status = ttk.Label(
            main, text="Keys: not loaded", foreground="red"
        )
        self.key_status.grid(row=4, column=0, columnspan=4, sticky="w", pady=(2, 5))

        ttk.Separator(main, orient="horizontal").grid(
            row=5, column=0, columnspan=4, sticky="ew", pady=8
        )

        # --- Encrypt section ---
        ttk.Label(
            main,
            text="Encrypt (Encapsulate + Stream Cipher):",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=6, column=0, columnspan=4, sticky="w")

        ttk.Button(
            main, text="4) Choose plaintext file...", command=self.on_choose_plain
        ).grid(row=7, column=0, sticky="w", pady=(3, 2))
        ttk.Entry(main, textvariable=self.plain_in_var, width=60).grid(
            row=7, column=1, columnspan=3, sticky="ew", padx=(5, 0)
        )

        ttk.Button(
            main, text="5) Encrypt → Save bundle.json", command=self.on_encrypt
        ).grid(row=8, column=0, sticky="w", pady=(3, 2))
        ttk.Entry(main, textvariable=self.bundle_out_var, width=60).grid(
            row=8, column=1, columnspan=3, sticky="ew", padx=(5, 0)
        )

        ttk.Separator(main, orient="horizontal").grid(
            row=9, column=0, columnspan=4, sticky="ew", pady=8
        )

        # --- Decrypt section ---
        ttk.Label(
            main,
            text="Decrypt (Decapsulate + AES/DES):",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=10, column=0, columnspan=4, sticky="w")

        ttk.Button(
            main, text="6) Choose bundle.json...", command=self.on_choose_bundle
        ).grid(row=11, column=0, sticky="w", pady=(3, 2))
        ttk.Entry(main, textvariable=self.bundle_in_var, width=60).grid(
            row=11, column=1, columnspan=3, sticky="ew", padx=(5, 0)
        )

        ttk.Button(
            main, text="7) Decrypt → Save plaintext", command=self.on_decrypt
        ).grid(row=12, column=0, sticky="w", pady=(3, 2))
        ttk.Entry(main, textvariable=self.plain_out_var, width=60).grid(
            row=12, column=1, columnspan=3, sticky="ew", padx=(5, 0)
        )

        # --- Story / Animation section ---
        story_frame = ttk.LabelFrame(main, text="What is happening now?")
        story_frame.grid(
            row=13, column=0, columnspan=4, sticky="nsew", pady=(8, 0)
        )

        self.story_text = tk.Text(
            story_frame, height=8, wrap="word", state="disabled"
        )
        self.story_text.pack(fill="both", expand=True)

        # --- Progress bar ---
        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.grid(
            row=14, column=0, columnspan=4, sticky="ew", pady=(4, 0)
        )

        # --- Status bar ---
        status_label = ttk.Label(
            main, textvariable=self.status_var, foreground="blue"
        )
        status_label.grid(
            row=15, column=0, columnspan=4, sticky="w", pady=(8, 0)
        )

        # Column & row weights
        for col in range(4):
            main.columnconfigure(col, weight=1)
        main.rowconfigure(13, weight=1)  # story frame expands

    # -------------------------------------------------------------------------
    # Story / animation helpers
    # -------------------------------------------------------------------------
    def _story_reset(self, title: str):
        self.story_text.config(state="normal")
        self.story_text.delete("1.0", "end")
        self.story_text.insert("end", f"{title}:\n\n")
        self.story_text.config(state="disabled")

    def _story_append(self, line: str):
        self.story_text.config(state="normal")
        self.story_text.insert("end", f"• {line}\n")
        self.story_text.see("end")
        self.story_text.config(state="disabled")

    def _story_animate(self, lines, delay_ms: int = 400):
        """
        Animate showing the lines one-by-one.
        """

        def step(i=0):
            if i < len(lines):
                self._story_append(lines[i])
                self.root.after(delay_ms, step, i + 1)

        step()

    # -------------------------------------------------------------------------
    # Busy indicator (progress bar + cursor)
    # -------------------------------------------------------------------------
    def _set_busy(self, busy: bool):
        if busy:
            self.progress.start(10)
            self.root.config(cursor="watch")
        else:
            self.progress.stop()
            self.root.config(cursor="")
        self.root.update_idletasks()

    # -------------------------------------------------------------------------
    # Keypair handlers
    # -------------------------------------------------------------------------
    def on_keygen(self):
        try:
            self._set_busy(True)
            start = time.perf_counter()
            pk, sk = self.kem.keygen()
            elapsed_ms = (time.perf_counter() - start) * 1000

            self.keypair = KeyPair(public_key=pk, secret_key=sk)
            self.key_status.config(
                text="Keys: generated (not yet saved)", foreground="green"
            )
            self.status_var.set(
                f"Generated new ML-KEM-512 keypair in {elapsed_ms:.2f} ms"
            )

            self._story_reset("Key generation")
            self._story_animate(
                [
                    "Step 1: Generating quantum-safe noise-based secret shapes.",
                    "Step 2: Building public matrix A in modular arithmetic.",
                    "Step 3: Compressing lattice vectors into public + secret key.",
                    f"Done in {elapsed_ms:.2f} ms.",
                ]
            )
        finally:
            self._set_busy(False)

    def on_save_keypair(self):
        if self.keypair is None:
            messagebox.showerror("Error", "No keypair to save. Generate or load first.")
            return

        path = filedialog.asksaveasfilename(
            title="Save keypair JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            self._set_busy(True)
            self.keystore.save(path, self.keypair)
            self.keyfile_var.set(path)
            self.key_status.config(
                text=f"Keys: saved ({os.path.basename(path)})", foreground="green"
            )
            self.status_var.set(f"Keypair saved to {path}")
            self._story_reset("Keypair saved")
            self._story_append(f"Keypair stored in JSON file: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keypair:\n{e}")
        finally:
            self._set_busy(False)

    def on_load_keypair(self):
        path = filedialog.askopenfilename(
            title="Load keypair JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            self._set_busy(True)
            kp = self.keystore.load(path)
            self.keypair = kp
            # Also load into kem instance
            self.kem.pk = kp.public_key
            self.kem.sk = kp.secret_key

            self.keyfile_var.set(path)
            self.key_status.config(
                text=f"Keys: loaded ({os.path.basename(path)})", foreground="green"
            )
            self.status_var.set(f"Loaded keypair from {path}")
            self._story_reset("Keypair loaded")
            self._story_append("Public and secret key loaded from JSON file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keypair:\n{e}")
        finally:
            self._set_busy(False)

    # -------------------------------------------------------------------------
    # Encrypt handlers
    # -------------------------------------------------------------------------
    def on_choose_plain(self):
        path = filedialog.askopenfilename(
            title="Select plaintext file",
            filetypes=[
                ("Text files", "*.txt;*.md;*.json"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.plain_in_var.set(path)

    def _get_selected_symmetric(self):
        """
        Returns (scheme_label, mode, WrapperClass) from SYMMETRIC_ALGS registry.
        """
        scheme_label = self.cipher_var.get()
        if scheme_label not in SYMMETRIC_ALGS:
            raise ValueError(f"Unknown symmetric scheme: {scheme_label}")

        # Expected registry format: { "AES-256-CBC": ("AES", "CBC", AESWrapper), ... }
        _, mode, Wrapper = SYMMETRIC_ALGS[scheme_label]
        return scheme_label, mode, Wrapper

    def _derive_sym_key(self, shared_secret: bytes, Wrapper):
        """
        Derive a symmetric key of exact length needed by the wrapper.
        """
        key_len = Wrapper.key_len_bytes() 
        return kdf_sha256(shared_secret, key_len)


    def on_encrypt(self):
        if self.keypair is None:
            messagebox.showerror("Error", "You must generate or load a keypair first.")
            return

        in_path = self.plain_in_var.get()
        if not in_path or not os.path.exists(in_path):
            messagebox.showerror("Error", "Please choose a valid plaintext file.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Save cipher bundle",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            self._set_busy(True)
            t0 = time.perf_counter()

            # 1) Read plaintext
            with open(in_path, "rb") as f:
                plaintext = f.read()

            # 2) Choose symmetric algorithm (AES/DES) from dropdown
            scheme_label, mode, Wrapper = self._get_selected_symmetric()

            # 3) ML-KEM encapsulation -> (kem_ciphertext, shared_secret)
            t_kem0 = time.perf_counter()
            kem_ct, shared_secret = self.kem.encaps(self.keypair.public_key)
            t_kem_ms = (time.perf_counter() - t_kem0) * 1000

            # 4) Derive symmetric key from shared secret using KDF
            t_kdf0 = time.perf_counter()
            sym_key = self._derive_sym_key(shared_secret, Wrapper)
            t_kdf_ms = (time.perf_counter() - t_kdf0) * 1000

            # 5) Symmetric encrypt
            t_sym0 = time.perf_counter()
            sym_ct, sym_iv = Wrapper.encrypt(sym_key, plaintext, mode)
            t_sym_ms = (time.perf_counter() - t_sym0) * 1000

            total_ms = (time.perf_counter() - t0) * 1000

            # 6) Save bundle (IMPORTANT: unified structure)
            bundle = {
                "scheme": f"ML-KEM-512 + {scheme_label}",
                "mlkem": {
                    "ciphertext_hex": kem_ct.hex(),
                },
                "symmetric": {
                    "alg": scheme_label,
                    "mode": mode,
                    "iv_hex": sym_iv.hex() if sym_iv else "",
                    "ciphertext_hex": sym_ct.hex(),
                    "kdf": "kdf_sha256(shared_secret) -> sym_key",
                    "key_len_bytes": len(sym_key),
                },
                "meta": {
                    "input_filename": os.path.basename(in_path),
                    "plaintext_len": len(plaintext),
                    "timing_ms": {
                        "kem_encaps": round(t_kem_ms, 3),
                        "kdf": round(t_kdf_ms, 3),
                        "sym_encrypt": round(t_sym_ms, 3),
                        "total": round(total_ms, 3),
                    },
                },
            }

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2)

            self.bundle_out_var.set(out_path)
            self.status_var.set(f"Encrypted using {scheme_label} in {total_ms:.2f} ms → {out_path}")

            self._story_reset("Hybrid Encryption (ML-KEM + AES/DES)")
            self._story_animate([
                "Step 1: Read plaintext bytes from file.",
                "Step 2: ML-KEM encapsulation → (KEM ciphertext + shared secret).",
                f"Step 3: KDF derives {len(sym_key)}-byte symmetric key.",
                f"Step 4: Encrypt plaintext using {scheme_label} ({mode}).",
                "Step 5: Save bundle.json with KEM ciphertext + symmetric ciphertext + IV + timings.",
                f"Done in {total_ms:.2f} ms.",
            ])

            messagebox.showinfo("Success", f"Encryption complete using {scheme_label}.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
            self._story_append(f"Error: {e}")
        finally:
            self._set_busy(False)


    # -------------------------------------------------------------------------
    # Decrypt handlers
    # -------------------------------------------------------------------------
    def on_choose_bundle(self):
        path = filedialog.askopenfilename(
            title="Select cipher bundle.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.bundle_in_var.set(path)

    def on_decrypt(self):
        if self.keypair is None:
            messagebox.showerror("Error", "You must load the matching secret keypair first.")
            return

        bundle_path = self.bundle_in_var.get()
        if not bundle_path or not os.path.exists(bundle_path):
            messagebox.showerror("Error", "Please choose a valid cipher bundle file.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Save decrypted plaintext",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            self._set_busy(True)
            t0 = time.perf_counter()

            with open(bundle_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            # --- Parse unified bundle structure ---
            kem_ct = bytes.fromhex(bundle["mlkem"]["ciphertext_hex"])

            sym = bundle["symmetric"]
            scheme_label = sym["alg"]
            mode = sym["mode"]
            sym_ct = bytes.fromhex(sym["ciphertext_hex"])
            iv_hex = sym.get("iv_hex", "")
            sym_iv = bytes.fromhex(iv_hex) if iv_hex else b""

            if scheme_label not in SYMMETRIC_ALGS:
                raise ValueError(f"Bundle requests unknown symmetric alg: {scheme_label}")

            _, _, Wrapper = SYMMETRIC_ALGS[scheme_label]

            # 1) ML-KEM decapsulation -> shared secret
            t_kem0 = time.perf_counter()
            shared_secret = self.kem.decaps(kem_ct, self.keypair.secret_key)
            t_kem_ms = (time.perf_counter() - t_kem0) * 1000

            # 2) Re-derive symmetric key (same KDF)
            t_kdf0 = time.perf_counter()
            sym_key = self._derive_sym_key(shared_secret, Wrapper)
            t_kdf_ms = (time.perf_counter() - t_kdf0) * 1000

            # 3) Symmetric decrypt
            t_sym0 = time.perf_counter()
            plaintext = Wrapper.decrypt(sym_key, sym_ct, mode, sym_iv)
            t_sym_ms = (time.perf_counter() - t_sym0) * 1000

            with open(out_path, "wb") as f:
                f.write(plaintext)

            total_ms = (time.perf_counter() - t0) * 1000
            self.plain_out_var.set(out_path)
            self.status_var.set(f"Decrypted using {scheme_label} in {total_ms:.2f} ms → {out_path}")

            self._story_reset("Hybrid Decryption (ML-KEM + AES/DES)")
            self._story_animate([
                "Step 1: Load bundle.json and extract KEM + symmetric parts.",
                "Step 2: ML-KEM decapsulation → shared secret recovered.",
                f"Step 3: KDF regenerates the same {len(sym_key)}-byte symmetric key.",
                f"Step 4: Decrypt using {scheme_label} ({mode}) + IV.",
                "Step 5: Write plaintext back to file.",
                f"Done in {total_ms:.2f} ms.",
            ])

            messagebox.showinfo("Success", f"Decryption complete using {scheme_label}.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            self._story_append(f"Error: {e}")
        finally:
            self._set_busy(False)

def run():
    root = tk.Tk()
    app = MLKEMGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    run()
