import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

BASE = Path(__file__).resolve().parent
PRIVATE_DIR = BASE / "private_keys"
PUBLIC_DIR = BASE / "public_keys"
SIG_DIR = BASE / "signatures"
DOCS_DIR = BASE / "documents"
TRUST_FILE = BASE / "trusted" / "trusted_keys.json"

for d in (PRIVATE_DIR, PUBLIC_DIR, SIG_DIR, DOCS_DIR, TRUST_FILE.parent):
    d.mkdir(exist_ok=True)


def ask(prompt, default=""):
    shown = f" [{default}]" if default else ""
    value = input(f"{prompt}{shown}: ").strip().strip('"').strip("'") or default
    return os.path.expanduser(value) if value.startswith("~") else value


def ask_path(prompt):
    while True:
        value = ask(prompt)
        if value:
            return Path(value)
        print("Path required")


def fingerprint(pub):
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def load_trust():
    return json.loads(TRUST_FILE.read_text()) if TRUST_FILE.exists() else {}


def load_public(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key


def generate_keys():
    signer = ask("Signer name", "author")
    priv_path = PRIVATE_DIR / f"{signer}_private.pem"
    pub_path = PUBLIC_DIR / f"{signer}_public.pem"
    if priv_path.exists() and ask("Keys exist. Overwrite? (yes/no)", "no") != "yes":
        print("Cancelled")
        return
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    pub_path.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Private key: {priv_path}")
    print(f"Public key: {pub_path}")
    print(f"Fingerprint: {fingerprint(priv.public_key())}")


def create_text():
    name = ask("File name", "mytext")
    if not name.endswith(".txt"):
        name += ".txt"
    path = DOCS_DIR / name
    if path.exists() and ask("File exists. Overwrite? (yes/no)", "no") != "yes":
        print("Cancelled")
        return
    print("Type your text. Enter an empty line to finish")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    path.write_bytes("\n".join(lines).encode("utf-8"))
    print(f"Saved: {path}")


def sign_file():
    doc = ask_path("Path of text file to sign")
    if not doc.is_file():
        print(f"File not found: {doc.resolve()}")
        return
    priv_path = ask_path("Path of private key file")
    if not priv_path.is_file():
        print(f"File not found: {priv_path.resolve()}")
        return
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    sig_path = SIG_DIR / f"{doc.name}.sig"
    sig_path.write_bytes(priv.sign(doc.read_bytes()))
    print(f"Signature saved: {sig_path}")


def trust_key():
    signer = ask("Signer name", "author")
    pub_path = ask_path("Path of public key to approve")
    if not pub_path.is_file():
        print(f"File not found: {pub_path.resolve()}")
        return
    fp = fingerprint(load_public(pub_path))
    print(f"Fingerprint: {fp}")
    if ask("Type APPROVE to trust this key") != "APPROVE":
        print("Not trusted")
        return
    trust = load_trust()
    trust[signer] = fp
    TRUST_FILE.write_text(json.dumps(trust, indent=2))
    print(f"Trusted: {signer}")


def verify_file():
    doc = ask_path("Path of text file to verify")
    sig_path = ask_path("Path of signature file")
    pub_path = ask_path("Path of public key file")
    signer = ask("Claimed signer name", "author")
    for p in (doc, sig_path, pub_path):
        if not p.is_file():
            print(f"File not found: {p.resolve()}")
            return
    pub = load_public(pub_path)
    try:
        pub.verify(sig_path.read_bytes(), doc.read_bytes())
        valid = True
    except InvalidSignature:
        valid = False
    trusted = load_trust().get(signer) == fingerprint(pub)
    print(f"Signature valid: {'yes' if valid else 'no'}")
    print(f"Key trusted: {'yes' if trusted else 'no'}")
    print("Result: " + ("ACCEPTED" if valid and trusted else "REJECTED"))


ACTIONS = {"1": generate_keys, "2": create_text, "3": sign_file, "4": trust_key, "5": verify_file}

while True:
    print("\nTrustedSeal")
    print("1. Generate keys")
    print("2. Create a text file")
    print("3. Sign a file")
    print("4. Trust a public key")
    print("5. Verify a file")
    print("6. Exit")
    choice = input("Choose: ").strip()
    if choice == "6":
        break
    action = ACTIONS.get(choice)
    if not action:
        print("Invalid choice")
        continue
    try:
        action()
    except Exception as exc:
        print(f"Error: {exc}")
