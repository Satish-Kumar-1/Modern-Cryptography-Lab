"""
crypto_utils.py - Ed25519 helper functions for the document-signing project.

All cryptography is done by the `cryptography` library. Nothing is implemented
from scratch. This module separates two kinds of problems:
  * InputError      -> the application could not run the check (missing file,
                       malformed key file, ...). NOT a statement about authenticity.
  * VerifyResult(ok=False) -> the check ran and the signature did NOT verify.
"""
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_LENGTH = 64  # An Ed25519 signature is always 64 bytes.


class InputError(Exception):
    """Raised for missing/unreadable/malformed inputs (not a crypto failure)."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool       # True only if the signature cryptographically verified
    reason: str    # Human-readable explanation


# ---------------------------------------------------------------- file helpers
def read_bytes(path):
    """Read a file's exact bytes, converting OS errors into InputError."""
    p = Path(path)
    try:
        return p.read_bytes()
    except FileNotFoundError:
        raise InputError(f"File not found: {p}") from None
    except OSError as exc:
        raise InputError(f"Cannot read {p}: {exc.strerror}") from None


def _write_private_file(path, data, overwrite):
    """Create a file readable/writable only by the owner (mode 600)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(p, flags, 0o600)
    except FileExistsError:
        raise InputError(
            f"{p} already exists. Refusing to overwrite a key (use --force)."
        ) from None
    except OSError as exc:
        raise InputError(f"Cannot write {p}: {exc.strerror}") from None
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(p, 0o600)  # enforce even if the file pre-existed


def _write_file(path, data):
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    except OSError as exc:
        raise InputError(f"Cannot write {p}: {exc.strerror}") from None


# --------------------------------------------------------------- key handling
def generate_keypair(private_path, public_path, overwrite=False):
    """
    Generate an Ed25519 key pair with the library's secure generator.
    Private key -> PKCS#8 PEM, unencrypted, file mode 600 (outside submission).
    Public key  -> SubjectPublicKeyInfo PEM (safe to share).
    Returns the public key's SHA-256 fingerprint (hex).
    """
    if not overwrite and Path(public_path).exists():
        raise InputError(f"{public_path} already exists (use --force to replace).")
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_private_file(private_path, private_pem, overwrite)
    _write_file(public_path, public_pem)
    return _fingerprint_of(private_key.public_key())


def load_private_key(path):
    data = read_bytes(path)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise InputError(f"{path} is not a valid unencrypted PEM private key.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise InputError(f"{path} is not an Ed25519 private key.")
    return key


def load_public_key(path):
    data = read_bytes(path)
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise InputError(f"{path} is not a valid PEM public key.") from None
    if not isinstance(key, Ed25519PublicKey):
        raise InputError(f"{path} is not an Ed25519 public key.")
    return key


def _fingerprint_of(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()


def fingerprint(public_key_path):
    """SHA-256 of the raw 32-byte public key, as lowercase hex."""
    return _fingerprint_of(load_public_key(public_key_path))


def _normalize_fp(text):
    return text.replace(":", "").replace(" ", "").strip().lower()


# ------------------------------------------------------------ sign and verify
def sign_file(document_path, private_key_path, signature_path):
    """Sign the document's exact bytes. The document is only read, never written."""
    if Path(signature_path).resolve() == Path(document_path).resolve():
        raise InputError("Signature output path must differ from the document path.")
    document = read_bytes(document_path)
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(document)  # Ed25519 signs the message directly
    _write_file(signature_path, signature)
    return Path(signature_path)


def verify_file(document_path, signature_path, public_key_path):
    """
    Verify signature over the document bytes with the supplied public key.
    Raises InputError for unusable inputs; otherwise returns a VerifyResult.
    """
    document = read_bytes(document_path)
    signature = read_bytes(signature_path)
    public_key = load_public_key(public_key_path)

    if len(signature) != SIGNATURE_LENGTH:
        return VerifyResult(
            False,
            f"Malformed signature: expected {SIGNATURE_LENGTH} bytes, got {len(signature)}.",
        )
    try:
        public_key.verify(signature, document)
    except InvalidSignature:
        return VerifyResult(
            False, "Signature does NOT match this document and public key."
        )
    return VerifyResult(
        True, "Signature is valid for this exact document under the supplied public key."
    )


def verify_with_trusted_fingerprint(document_path, signature_path, public_key_path,
                                    trusted_fingerprint):
    """
    Trusted-key verification: first check that the supplied public key matches a
    fingerprint obtained through an independent, authenticated channel.
    """
    actual = fingerprint(public_key_path)
    if actual != _normalize_fp(trusted_fingerprint):
        return VerifyResult(
            False,
            "UNTRUSTED KEY: its fingerprint does not match the trusted fingerprint. "
            "Signature not accepted.",
        )
    return verify_file(document_path, signature_path, public_key_path)