#!/usr/bin/env python3
"""
crypto_tool.py - Secure file encryption and tamper detection with AES-256-GCM.

Encrypted file layout (written by `encrypt`, read by `decrypt`):

    | nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes) |

Usage:
    python crypto_tool.py keygen  -k key.bin
    python crypto_tool.py encrypt -k key.bin -i sample.txt -o sample.enc
    python crypto_tool.py decrypt -k key.bin -i sample.enc -o recovered.txt
"""

import argparse
import hashlib
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32    # bytes -> AES-256
NONCE_SIZE = 12  # bytes -> 96-bit nonce, the recommended size for GCM
TAG_SIZE = 16    # bytes -> 128-bit authentication tag


class CryptoError(Exception):
    """Raised for any user-facing failure (bad key, bad file, tampering...)."""


# ---------------------------------------------------------------- helpers

def read_file(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise CryptoError(f"{what} not found: {path}")
    except OSError as e:
        raise CryptoError(f"Cannot read {what} '{path}': {e}")


def write_file(path: str, data: bytes) -> None:
    """Write via a temp file so a failed write never leaves a partial output."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise CryptoError(f"Cannot write '{path}': {e}")


def load_key(path: str) -> bytes:
    key = read_file(path, "Key file")
    if len(key) != KEY_SIZE:
        raise CryptoError(
            f"Invalid key length: {len(key)} bytes (expected {KEY_SIZE})."
        )
    return key


def sha256_file(path: str) -> str:
    return hashlib.sha256(read_file(path, "File")).hexdigest()


# --------------------------------------------------------------- commands

def generate_key(key_path: str) -> None:
    # os.urandom uses the OS cryptographically secure RNG
    key = os.urandom(KEY_SIZE)
    write_file(key_path, key)
    try:
        os.chmod(key_path, 0o600)  # owner read/write only (no-op on some OSes)
    except OSError:
        pass
    print(f"[OK] {KEY_SIZE * 8}-bit key written to {key_path}")


def encrypt_file(key_path: str, in_path: str, out_path: str) -> None:
    key = load_key(key_path)
    plaintext = read_file(in_path, "Input file")

    nonce = os.urandom(NONCE_SIZE)  # fresh random nonce for EVERY encryption
    # AESGCM.encrypt returns ciphertext || tag (tag is the last 16 bytes)
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)

    write_file(out_path, nonce + ct_and_tag)
    print(f"[OK] Encrypted '{in_path}' -> '{out_path}'")
    print(f"     nonce      : {nonce.hex()}")
    print(f"     ciphertext : {len(ct_and_tag) - TAG_SIZE} bytes")
    print(f"     tag        : {ct_and_tag[-TAG_SIZE:].hex()}")
    print(f"     SHA-256 of original: {hashlib.sha256(plaintext).hexdigest()}")


def decrypt_file(key_path: str, in_path: str, out_path: str) -> None:
    key = load_key(key_path)
    blob = read_file(in_path, "Encrypted file")

    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise CryptoError(
            "Encrypted file is too short or truncated "
            f"({len(blob)} bytes, minimum {NONCE_SIZE + TAG_SIZE})."
        )

    nonce = blob[:NONCE_SIZE]
    ct_and_tag = blob[NONCE_SIZE:]  # ciphertext || tag

    try:
        plaintext = AESGCM(key).decrypt(nonce, ct_and_tag, None)
    except InvalidTag:
        # Tag check failed: nothing is written, no plaintext is released.
        raise CryptoError(
            "Decryption FAILED: authentication tag mismatch. "
            "The file was modified, the tag is invalid, or the key is wrong."
        )

    # Only reached if authentication succeeded
    write_file(out_path, plaintext)
    print(f"[OK] Authentication passed. Decrypted '{in_path}' -> '{out_path}'")
    print(f"     SHA-256 of recovered: {hashlib.sha256(plaintext).hexdigest()}")


def verify_files(original: str, recovered: str) -> None:
    h1, h2 = sha256_file(original), sha256_file(recovered)
    print(f"original : {h1}\nrecovered: {h2}")
    if h1 == h2:
        print("[OK] Files are IDENTICAL.")
    else:
        raise CryptoError("Files DIFFER.")


# -------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AES-256-GCM file encryption tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate a random 256-bit key file")
    g.add_argument("-k", "--key", required=True, help="output key file")

    for name, helptext in (("encrypt", "encrypt a file"),
                           ("decrypt", "decrypt and verify a file")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("-k", "--key", required=True, help="key file")
        s.add_argument("-i", "--input", required=True, help="input file")
        s.add_argument("-o", "--output", required=True, help="output file")

    v = sub.add_parser("verify", help="compare SHA-256 of two files")
    v.add_argument("original")
    v.add_argument("recovered")
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.cmd == "keygen":
            generate_key(args.key)
        elif args.cmd == "encrypt":
            encrypt_file(args.key, args.input, args.output)
        elif args.cmd == "decrypt":
            decrypt_file(args.key, args.input, args.output)
        elif args.cmd == "verify":
            verify_files(args.original, args.recovered)
    except CryptoError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
