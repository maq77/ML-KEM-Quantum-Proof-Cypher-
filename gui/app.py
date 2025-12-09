import os
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.mlkem_ffi import MLKEM512
from core.stream_cipher import SimpleStreamCipher
from core.key_store import KeyStore, KeyPair


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
            value="ML-KEM-512 + SimpleStreamCipher (Quantum-safe)"
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
            text="ML-KEM-512 + SimpleStreamCipher\n(C++ quantum-safe core + Python GUI)",
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
            values=[
                "ML-KEM-512 + SimpleStreamCipher (Quantum-safe)",
                "AES-256-GCM (placeholder)",
                "ChaCha20-Poly1305 (placeholder)",
                "RSA-2048 + AES-256 (placeholder)",
            ],
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
            text="Decrypt (Decapsulate + Stream Cipher):",
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

    def on_encrypt(self):
        # Only ML-KEM implemented
        if not self.cipher_var.get().startswith("ML-KEM-512"):
            messagebox.showinfo(
                "Not implemented",
                "Currently only 'ML-KEM-512 + SimpleStreamCipher' is implemented in this demo.",
            )
            return

        if self.keypair is None:
            messagebox.showerror(
                "Error", "You must generate or load a keypair first."
            )
            return

        in_path = self.plain_in_var.get()
        if not in_path or not os.path.exists(in_path):
            messagebox.showerror(
                "Error", "Please choose a valid plaintext file."
            )
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
            start = time.perf_counter()

            with open(in_path, "rb") as f:
                plaintext = f.read()

            # Encapsulate to get ML-KEM shared secret
            ct, ss = self.kem.encaps(self.keypair.public_key)
            cipher = SimpleStreamCipher(ss)
            stream_ct = cipher.encrypt(plaintext)

            bundle = {
                "scheme": "ML-KEM-512 + SimpleStreamCipher",
                "pkey_hex": self.keypair.public_key.hex(),
                "ciphertext_mlkem_hex": ct.hex(),
                "stream_ciphertext_hex": stream_ct.hex(),
            }

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2)

            elapsed_ms = (time.perf_counter() - start) * 1000
            self.bundle_out_var.set(out_path)
            self.status_var.set(
                f"Encrypted and saved bundle to {out_path} in {elapsed_ms:.2f} ms"
            )
            self._story_reset("Encrypting with ML-KEM-512 + Stream Cipher")
            self._story_animate(
                [
                    "Step 1: Using the public key to hide a random secret in lattice noise.",
                    "Step 2: Deriving a 32-byte shared secret from the encapsulated message.",
                    "Step 3: Expanding the shared secret into a keystream with SHA-256.",
                    "Step 4: XOR-ing keystream with your file bytes (stream cipher).",
                    f"Done: bundle.json contains ML-KEM ciphertext + encrypted file (in {elapsed_ms:.2f} ms).",
                ]
            )
            messagebox.showinfo(
                "Success", "Encapsulation + encryption complete."
            )
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
        # Only ML-KEM implemented
        if not self.cipher_var.get().startswith("ML-KEM-512"):
            messagebox.showinfo(
                "Not implemented",
                "Currently only 'ML-KEM-512 + SimpleStreamCipher' is implemented in this demo.",
            )
            return

        if self.keypair is None:
            messagebox.showerror(
                "Error", "You must load the matching secret keypair first."
            )
            return

        bundle_path = self.bundle_in_var.get()
        if not bundle_path or not os.path.exists(bundle_path):
            messagebox.showerror(
                "Error", "Please choose a valid cipher bundle file."
            )
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
            start = time.perf_counter()

            with open(bundle_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            ct_hex = bundle["ciphertext_mlkem_hex"]
            stream_ct_hex = bundle["stream_ciphertext_hex"]

            ct = bytes.fromhex(ct_hex)
            stream_ct = bytes.fromhex(stream_ct_hex)

            # Recover shared secret using secret key
            ss = self.kem.decaps(ct, self.keypair.secret_key)
            cipher = SimpleStreamCipher(ss)
            plaintext = cipher.decrypt(stream_ct)

            with open(out_path, "wb") as f:
                f.write(plaintext)

            elapsed_ms = (time.perf_counter() - start) * 1000
            self.plain_out_var.set(out_path)
            self.status_var.set(
                f"Decrypted plaintext saved to {out_path} in {elapsed_ms:.2f} ms"
            )
            self._story_reset("Decrypting with ML-KEM-512 + Stream Cipher")
            self._story_animate(
                [
                    "Step 1: Using the secret key to decode the lattice ciphertext.",
                    "Step 2: Recovering the same 32-byte shared secret.",
                    "Step 3: Regenerating the same keystream with SHA-256.",
                    "Step 4: XOR-ing keystream with the stream ciphertext to recover the file.",
                    f"Done: plaintext restored from bundle in {elapsed_ms:.2f} ms.",
                ]
            )
            messagebox.showinfo(
                "Success", "Decapsulation + decryption complete."
            )
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
