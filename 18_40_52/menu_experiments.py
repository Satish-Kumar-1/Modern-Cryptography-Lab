#!/usr/bin/env python3
"""
menu_experiments.py - Menu to run the security experiments one by one or all at once.

Run:  python menu_experiments.py
Needs crypto_tool.py and menu_tool.py in the same folder.
Results are shown on screen and appended (one line each) to logs/experiments_log.txt.
"""

import hashlib
import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_tool as ct
from menu_tool import WORK_DIR, pick_file, quiet

LOG_FILE = os.path.join("logs", "experiments_log.txt")
state = {"key": None, "enc": None, "orig": None, "demo": True}


def w(name):
    return os.path.join(WORK_DIR, name)


def log(name, result, detail):
    """One line on screen and one line in the log file."""
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {name} | {result} | {detail}\n")
    print(f"[{result}] {name}: {detail}")


# ------------------------------------------------------------------ setup

def use_demo():
    """Create (if missing) and select the demo key, sample file and encrypted file."""
    os.makedirs(WORK_DIR, exist_ok=True)
    if not os.path.exists(w("sample.txt")):
        with open(w("sample.txt"), "w") as f:
            f.write("Project 1: AES-256-GCM sample file.\n"
                    "Any change to the ciphertext or tag must be detected.\n")
    if not os.path.exists(w("key.bin")):
        quiet(ct.generate_key, w("key.bin"))
    if not os.path.exists(w("sample.enc")):
        quiet(ct.encrypt_file, w("key.bin"), w("sample.txt"), w("sample.enc"))
    state.update(key=w("key.bin"), enc=w("sample.enc"), orig=w("sample.txt"), demo=True)


def choose_own():
    enc = pick_file("Select your ENCRYPTED file:", w("sample.enc"))
    if not enc:
        return
    key = pick_file("Select its KEY file:", w("key.bin"))
    if not key:
        return
    state.update(key=key, enc=enc, orig=None, demo=False)
    print("[OK] Using your files.")


# ---------------------------------------------------------------- helpers

def try_decrypt(key, enc, out):
    """True only if decryption succeeded AND an output file was written."""
    if os.path.exists(out):
        os.remove(out)
    try:
        quiet(ct.decrypt_file, key, enc, out)
    except ct.CryptoError:
        pass
    return os.path.exists(out)


def ready():
    """Check the selected key really decrypts the selected file (baseline)."""
    try:
        ok = try_decrypt(state["key"], state["enc"], w("baseline.tmp"))
    finally:
        if os.path.exists(w("baseline.tmp")):
            os.remove(w("baseline.tmp"))
    if not ok:
        print("[!] This key cannot decrypt this file. Pick a matching pair (option 7) "
              "or use demo files (option 8).")
    return ok


def tamper(offset_fn, out_name):
    """Copy the encrypted file with one bit flipped; return (path, offset) or None."""
    blob = bytearray(ct.read_file(state["enc"], "Encrypted file"))
    if len(blob) <= ct.NONCE_SIZE + ct.TAG_SIZE:
        print("[!] This file has no ciphertext bytes to tamper with.")
        return None
    offset = offset_fn(len(blob))
    blob[offset] ^= 0x01
    ct.write_file(w(out_name), bytes(blob))
    return w(out_name), offset


# ------------------------------------------------------------ experiments

def exp1():
    name = "1 Ciphertext tampering"
    if not ready():
        return
    t = tamper(lambda n: ct.NONCE_SIZE, "tampered_ct.enc")  # first ciphertext byte
    if t:
        rejected = not try_decrypt(state["key"], t[0], w("out_exp1.tmp"))
        log(name, "PASS" if rejected else "FAIL",
            f"flipped byte {t[1]}; " + ("rejected, no output written" if rejected else "ACCEPTED"))


def exp2():
    name = "2 Tag modification"
    if not ready():
        return
    t = tamper(lambda n: n - 1, "tampered_tag.enc")  # last byte = inside the tag
    if t:
        rejected = not try_decrypt(state["key"], t[0], w("out_exp2.tmp"))
        log(name, "PASS" if rejected else "FAIL",
            f"flipped byte {t[1]} (tag); " + ("rejected, no output written" if rejected else "ACCEPTED"))


def exp3():
    name = "3 Wrong key"
    if not os.path.isfile(state["enc"]):
        print(f"[!] File not found: {state['enc']}")
        return
    ct.write_file(w("wrong_key.bin"), os.urandom(ct.KEY_SIZE))
    rejected = not try_decrypt(w("wrong_key.bin"), state["enc"], w("out_exp3.tmp"))
    log(name, "PASS" if rejected else "FAIL",
        "random wrong key " + ("rejected, no output written" if rejected else "ACCEPTED"))


def exp4():
    name = "4 Nonce reuse"
    aes = AESGCM(os.urandom(ct.KEY_SIZE))
    nonce = os.urandom(ct.NONCE_SIZE)  # reused on purpose: this is the bug being shown
    p1 = b"Transfer $100 to Alice, ref 0001"
    p2 = b"Transfer $999 to Bobby, ref 0002"
    c1 = aes.encrypt(nonce, p1, None)[:-ct.TAG_SIZE]
    c2 = aes.encrypt(nonce, p2, None)[:-ct.TAG_SIZE]
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    leaked = xor(c1, c2) == xor(p1, p2)
    recovered = xor(xor(c1, c2), p1) == p2  # attacker knows P1, recovers P2
    ok = leaked and recovered
    log(name, "PASS" if ok else "FAIL",
        "same nonce twice: C1^C2 == P1^P2, P2 recovered without the key" if ok else "unexpected result")


def exp5():
    name = "5 Correctness"
    if state["orig"] is None:
        state["orig"] = pick_file("Select ORIGINAL file to compare (Enter to skip):", None)
    out = w("recovered.txt")
    if not try_decrypt(state["key"], state["enc"], out):
        log(name, "FAIL", "decryption failed (wrong key or modified file)")
        return
    h_rec = hashlib.sha256(ct.read_file(out, "Recovered file")).hexdigest()
    if state["orig"] is None:
        log(name, "DONE", f"decrypted OK, no original given; SHA-256 {h_rec[:16]}...")
        return
    h_org = hashlib.sha256(ct.read_file(state["orig"], "Original file")).hexdigest()
    same = h_org == h_rec
    log(name, "PASS" if same else "FAIL",
        f"SHA-256 {h_org[:16]}... " + ("identical to recovered" if same else "DIFFERS from recovered"))


def run_all():
    for fn in (exp1, exp2, exp3, exp4, exp5):
        fn()


# ------------------------------------------------------------------- menu

ACTIONS = {"1": exp1, "2": exp2, "3": exp3, "4": exp4, "5": exp5,
           "6": run_all, "7": choose_own, "8": use_demo}


def show_menu():
    mode = "demo files" if state["demo"] else "your files"
    print(f"""
===== AES-GCM Experiments =====
Using: {mode}  (file: {state['enc']}, key: {state['key']})
 1. Ciphertext tampering
 2. Tag modification
 3. Wrong key
 4. Nonce reuse
 5. Correctness check
 6. Run ALL (1-5)
 7. Choose my own encrypted file + key
 8. Use demo files
 0. Exit""")


def main():
    use_demo()
    while True:
        show_menu()
        try:
            choice = input("Choose: ").strip()
            if choice == "0":
                break
            if choice in ACTIONS:
                try:
                    ACTIONS[choice]()
                except ct.CryptoError as e:
                    print(f"[FAILED] {e}")
            else:
                print("Please enter 0-8.")
        except (EOFError, KeyboardInterrupt):
            break
    print(f"Bye. Log: {LOG_FILE}")


if __name__ == "__main__":
    main()
