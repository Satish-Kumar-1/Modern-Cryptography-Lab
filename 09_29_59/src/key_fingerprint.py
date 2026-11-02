"""Public Key Fingerprinting and Trust Verification Module.

Person 1 & Person 2 Interface Contract.

Computes canonical cryptographic fingerprints of Ed25519 public keys to enable
out-of-band key authentication, preventing public-key substitution attacks
(Requirement 7 & Experiment 4).
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.key_manager import KeyManager


class KeyFingerprint:
    """Computes and compares cryptographic fingerprints of Ed25519 public keys."""

    @staticmethod
    def compute_fingerprint(
        public_key_source: Union[str, Path, bytes, ed25519.Ed25519PublicKey],
        algorithm: str = "sha256"
    ) -> str:
        """Compute a formatted SHA-256 fingerprint from an Ed25519 public key.

        The fingerprint is calculated over the canonical SubjectPublicKeyInfo (DER)
        representation of the public key.

        Args:
            public_key_source: Path to PEM, raw bytes, or Ed25519PublicKey object.
            algorithm: Hash algorithm name (default 'sha256').

        Returns:
            str: Colon-separated hex string, e.g. 'SHA256:3a:7f:81:...'
        """
        if isinstance(public_key_source, ed25519.Ed25519PublicKey):
            pub_key = public_key_source
        else:
            pub_key = KeyManager.load_public_key(public_key_source)

        der_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        hasher = getattr(hashlib, algorithm.lower())()
        hasher.update(der_bytes)
        digest = hasher.hexdigest()

        # Format with colons for human readability (OpenSSH / OpenSSL style)
        colon_formatted = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
        return f"{algorithm.upper()}:{colon_formatted}"

    @staticmethod
    def verify_fingerprint(
        public_key_source: Union[str, Path, bytes, ed25519.Ed25519PublicKey],
        expected_fingerprint: str
    ) -> bool:
        """Compare the actual public key fingerprint against a trusted out-of-band fingerprint.

        Uses constant-time comparison to resist timing side-channel attacks.

        Args:
            public_key_source: The public key to check.
            expected_fingerprint: The trusted out-of-band fingerprint.

        Returns:
            bool: True if fingerprints match, False otherwise.
        """
        try:
            actual = KeyFingerprint.compute_fingerprint(public_key_source)
            # Normalize whitespace and casing
            return hmac.compare_digest(actual.strip().lower(), expected_fingerprint.strip().lower())
        except Exception:
            return False
