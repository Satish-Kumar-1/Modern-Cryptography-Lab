"""Digital Signature-Based Document Verification System (Ed25519)

A secure, detached digital signature and verification suite implementing
RFC 8032 Edwards-curve Digital Signature Algorithm (Ed25519).
"""

from __future__ import annotations

from src.document_signer import DocumentSigner, SigningError
from src.key_fingerprint import KeyFingerprint
from src.key_manager import (
    CryptographicError,
    InvalidPassphraseError,
    KeyFormatError,
    KeyManagementError,
    KeyManager,
    PassphraseError,
)
from src.signature_verifier import SignatureVerifier, VerificationResult

__version__ = "1.0.0"
__author__ = "Aryan & Team"

__all__ = [
    "KeyManager",
    "DocumentSigner",
    "SignatureVerifier",
    "VerificationResult",
    "KeyFingerprint",
    "CryptographicError",
    "KeyManagementError",
    "KeyFormatError",
    "PassphraseError",
    "InvalidPassphraseError",
    "SigningError",
]
