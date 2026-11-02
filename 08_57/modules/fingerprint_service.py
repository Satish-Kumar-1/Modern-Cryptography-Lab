"""Public-key fingerprints: a short, comparable identifier for a public key.

A fingerprint is the SHA-256 hash of the raw 32-byte public key. Two people can
compare fingerprints over an independent channel (phone call, in person...) to
confirm they hold the same key.
"""

import hashlib
import hmac
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modules.validation import InputError


def compute_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the SHA-256 fingerprint as 64 lowercase hex characters.

    We hash the raw key bytes (not the PEM text) so the result does not depend on
    how the key file happens to be formatted.
    """
    raw_key = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw_key).hexdigest()


def format_fingerprint(fingerprint_hex: str) -> str:
    """AB:CD:EF:... (uppercase, byte pairs) so humans can read it aloud."""
    return ":".join(fingerprint_hex[i:i + 2] for i in range(0, len(fingerprint_hex), 2)).upper()


def normalize_fingerprint(text: str) -> str:
    """Accept colons, spaces, dashes and any letter case; return 64 lowercase hex chars."""
    cleaned = re.sub(r"[\s:\-]", "", text or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        raise InputError("That is not a valid SHA-256 fingerprint. It must contain exactly 64 hexadecimal characters "
                         "(0-9, a-f); colons and spaces are allowed.")
    return cleaned


def fingerprints_match(fingerprint_a: str, fingerprint_b: str) -> bool:
    """Compare two fingerprints, ignoring formatting. compare_digest is a constant-time comparison."""
    return hmac.compare_digest(normalize_fingerprint(fingerprint_a).encode(),
                               normalize_fingerprint(fingerprint_b).encode())
