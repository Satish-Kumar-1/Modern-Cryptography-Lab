#!/usr/bin/env python3
"""
menu_tool.py - Simple menu for AES-256-GCM key generation, encryption, decryption.

Run:  python menu_tool.py
Needs crypto_tool.py in the same folder.
"""

import contextlib
import io
import os

import crypto_tool as ct

WORK_DIR = "experiment_files"
HIDE_EXT = (".py", ".pyc", ".md", ".tmp")
HIDE_NAMES = {"requirements.txt"}


# ---------------------------------------------------------------- helpers

def quiet(fn, *args):
    """Run a crypto_tool function without its detailed printing."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args)


def list_files():
    """Files in the current folder and in experiment_files/ (if present)."""
    found = []
    for folder in (".", WORK_DIR):
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            path = name if folder == "." else os.path.join(folder, name)
            if (os.path.isfile(path) and not name.startswith(".")
                    and not name.endswith(HIDE_EXT) and name not in HIDE_NAMES):
                found.append(path)
    return found


def pick_file(label, default, must_exist=True):
    """Show files to choose from. Enter = default, number = list item, or type a path."""
    files = list_files()
    print(f"\n{label}")
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f}")
    shown = default if default else "skip"
    ans = input(f"Number, path, or Enter for [{shown}]: ").strip().strip('"')

    if ans == "":
        path = default
    elif ans.isdigit() and 1 <= int(ans) <= len(files):
        path = files[int(ans) - 1]
    else:
        path = ans

    if path is None:
        return None
    if must_exist and not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return None
    return path


def ask_output(label, default):
    """Ask for an output file name; confirm before overwriting."""
    path = input(f"\n{label} [{default}]: ").strip().strip('"') or default
    if os.path.exists(path):
        if input(f"'{path}' exists. Overwrite? (y/N): ").strip().lower() != "y":
            print("Cancelled.")
            return None
    return path


def run(action):
    """Run an action and show errors as one plain line."""
    try:
        action()
    except ct.CryptoError as e:
        print(f"[FAILED] {e}")


# ---------------------------------------------------------------- actions

def do_keygen():
    out = ask_output("Key file name", "key.bin")
    if out:
        quiet(ct.generate_key, out)
        print(f"[OK] 256-bit key saved to {out}")


def do_encrypt():
    src = pick_file("Select file to ENCRYPT:", "sample.txt")
    if not src:
        return
    key = pick_file("Select KEY file:", "key.bin")
    if not key:
        return
    out = ask_output("Encrypted file name", os.path.splitext(os.path.basename(src))[0] + ".enc")
    if out:
        quiet(ct.encrypt_file, key, src, out)
        print(f"[OK] Encrypted -> {out}")


def do_decrypt():
    enc = pick_file("Select ENCRYPTED file:", "sample.enc")
    if not enc:
        return
    key = pick_file("Select KEY file:", "key.bin")
    if not key:
        return
    out = ask_output("Decrypted file name", "recovered.txt")
    if out:
        quiet(ct.decrypt_file, key, enc, out)  # writes only if tag verifies
        print(f"[OK] Authentication passed. Decrypted -> {out}")


def do_verify():
    a = pick_file("Select ORIGINAL file:", "sample.txt")
    if not a:
        return
    b = pick_file("Select DECRYPTED file:", "recovered.txt")
    if not b:
        return
    same = ct.sha256_file(a) == ct.sha256_file(b)
    print("[OK] Files are IDENTICAL." if same else "[FAILED] Files DIFFER.")


# ------------------------------------------------------------------- menu

MENU = """
===== AES-GCM File Encryption =====
 1. Generate key
 2. Encrypt a file
 3. Decrypt a file
 4. Verify (original vs decrypted)
 0. Exit"""

ACTIONS = {"1": do_keygen, "2": do_encrypt, "3": do_decrypt, "4": do_verify}


def main():
    while True:
        print(MENU)
        try:
            choice = input("Choose: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if choice == "0":
            break
        if choice in ACTIONS:
            try:
                run(ACTIONS[choice])
            except (EOFError, KeyboardInterrupt):
                break
        else:
            print("Please enter 0-4.")
    print("Bye.")


if __name__ == "__main__":
    main()
