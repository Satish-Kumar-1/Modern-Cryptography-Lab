#!/usr/bin/env python3
"""
Project 4: Ed25519 document signing and verification.

Features:
- Generate Ed25519 key pairs
- Sign exact file bytes
- Verify signature against document + public key
- Compute public-key fingerprints
- Maintain a simple trusted-key store
- Verify using the trusted key for a named user
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ENC = serialization.Encoding.PEM
PRIV_FMT = serialization.PrivateFormat.PKCS8
PUB_FMT = serialization.PublicFormat.SubjectPublicKeyInfo

def read_bytes(path: str) -> bytes:
    return Path(path).read_bytes()

def write_bytes(path: str, data: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

def load_private_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")
    return key

def load_public_key(path: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key

def public_key_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(ENC, PUB_FMT).decode("ascii")

def public_key_der(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, PUB_FMT)

def fingerprint(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key_der(key)).hexdigest()


def cmd_keygen(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_path = outdir / f"{args.user}_private.pem"
    pub_path = outdir / f"{args.user}_public.pem"
    write_bytes(
        str(priv_path),
        private_key.private_bytes(ENC, PRIV_FMT, serialization.NoEncryption()),
    )
    write_bytes(str(pub_path), public_key.public_bytes(ENC, PUB_FMT))
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    print(f"Generated {args.user} key pair")
    print(f"Private: {priv_path} (keep secret; do not submit)")
    print(f"Public:  {pub_path}")
    print(f"Fingerprint: {fingerprint(public_key)}")
    return 0

def cmd_sign(args: argparse.Namespace) -> int:
    data = read_bytes(args.infile)
    private_key = load_private_key(args.key)

    # Ed25519 signs the exact byte string. No manual hash is needed.
    signature = private_key.sign(data)
    write_bytes(args.out, signature)
    print(f"Signed {args.infile} ({len(data)} bytes)")
    print(f"Signature: {args.out} ({len(signature)} bytes)")
    print(f"Signer public fingerprint: {fingerprint(private_key.public_key())}")
    return 0

def verify_bytes(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> int:
    try:
        public_key.verify(signature, data)
        print("VALID: signature verifies under the provided public key")
        return 0
    except InvalidSignature:
        print("INVALID: signature does not verify")
        return 1
    except ValueError as exc:
        print(f"INVALID: malformed input ({exc})")
        return 1

def cmd_verify(args: argparse.Namespace) -> int:
    data = read_bytes(args.infile)
    signature = read_bytes(args.sig)
    public_key = load_public_key(args.pub)
    print(f"Document: {args.infile}")
    print(f"Signature: {args.sig}")
    print(f"Public-key fingerprint: {fingerprint(public_key)}")
    return verify_bytes(data, signature, public_key)

def cmd_fingerprint(args: argparse.Namespace) -> int:
    public_key = load_public_key(args.pub)
    print(fingerprint(public_key))
    return 0

def cmd_trust(args: argparse.Namespace) -> int:
    public_key = load_public_key(args.pub)
    fp = fingerprint(public_key)
    store_path = Path(args.store)

    if store_path.exists():
        try:
            store = json.loads(store_path.read_text())
        except json.JSONDecodeError:
            store = {}
    else:
        store = {}

    if (
        args.user in store
        and store[args.user].get("fingerprint") != fp
        and not args.force
    ):
        print(
            f"ERROR: {args.user} is already trusted with a different fingerprint; "
            f"use --force to replace",
            file=sys.stderr,
        )
        return 2
    store[args.user] = {
        "fingerprint": fp,
        "public_key_pem": public_key_pem(public_key),
    }
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps(store, indent=2))
    print(f"Trusted {args.user} -> {fp}")
    print(f"Trust store: {store_path}")
    return 0

def cmd_verify_trusted(args: argparse.Namespace) -> int:
    store_path = Path(args.store)
    if not store_path.exists():
        raise ValueError(f"trust store not found: {store_path}")
    store = json.loads(store_path.read_text())
    if args.user not in store:
        raise ValueError(f"no trusted key for user {args.user}")
    entry = store[args.user]
    trusted_key = serialization.load_pem_public_key(
        entry["public_key_pem"].encode("ascii")
    )
    if not isinstance(trusted_key, Ed25519PublicKey):
        raise ValueError("trusted key is not Ed25519")
    actual_fp = fingerprint(trusted_key)
    if actual_fp != entry["fingerprint"]:
        print("INVALID: trust-store fingerprint mismatch", file=sys.stderr)
        return 1
    data = read_bytes(args.infile)
    signature = read_bytes(args.sig)
    print(f"Trusted user: {args.user}")
    print(f"Trusted fingerprint: {actual_fp}")
    return verify_bytes(data, signature, trusted_key)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Project 4: Ed25519 document signing and verification"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="Generate an Ed25519 key pair")
    p.add_argument("--user", required=True)
    p.add_argument("--outdir", default="keys")
    p.set_defaults(func=cmd_keygen)
    p = sub.add_parser("sign", help="Sign a document")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_sign)
    p = sub.add_parser("verify", help="Verify with an explicitly supplied public key")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--sig", required=True)
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("fingerprint", help="Print SHA-256 fingerprint of a public key")
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_fingerprint)
    p = sub.add_parser("trust", help="Add/update a trusted public key")
    p.add_argument("--user", required=True)
    p.add_argument("--pub", required=True)
    p.add_argument("--store", default="trusted_keys.json")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_trust)
    p = sub.add_parser(
        "verify-trusted",
        help="Verify using the trusted key stored for a named user",
    )
    p.add_argument("--user", required=True)
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--sig", required=True)
    p.add_argument("--store", default="trusted_keys.json")
    p.set_defaults(func=cmd_verify_trusted)
    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
    