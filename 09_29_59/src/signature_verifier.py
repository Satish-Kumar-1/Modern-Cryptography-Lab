"""Signature Verifier Module for Ed25519 Detached Digital Signatures.

Person 1 & Person 2 Interface Contract.

This module provides independent verification of detached Ed25519 signatures
against documents and public keys.
Per Assignment Requirement 6:
"Display a clear result indicating whether verification succeeded or failed.
 The application should handle modified documents, incorrect public keys,
 invalid signatures, and malformed inputs without crashing."
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.key_manager import (
    KeyFormatError,
    KeyManager,
)


class VerificationResult:
    """Structured result returned by signature verification."""

    def __init__(self, is_valid: bool, message: str, details: Optional[str] = None):
        self.is_valid: bool = is_valid
        self.message: str = message
        self.details: Optional[str] = details

    def __bool__(self) -> bool:
        return self.is_valid

    def __repr__(self) -> str:
        status = "VALID" if self.is_valid else "INVALID"
        return f"<VerificationResult status={status} message={self.message!r}>"


class SignatureVerifier:
    """Verifies detached Ed25519 digital signatures safely without crashing."""

    @staticmethod
    def verify_bytes(
        data: bytes,
        signature: bytes,
        public_key: ed25519.Ed25519PublicKey
    ) -> bool:
        """Verify an exact sequence of bytes against an Ed25519 signature and public key.

        Args:
            data: Exact byte payload that was signed.
            signature: 64-byte Ed25519 signature.
            public_key: Ed25519 public key instance.

        Returns:
            bool: True if signature is cryptographically valid, False otherwise.
        """
        if not isinstance(data, (bytes, bytearray)):
            return False
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            return False
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False

        try:
            public_key.verify(bytes(signature), bytes(data))
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    @classmethod
    def verify_document(
        cls,
        document_path: Union[str, Path],
        signature_source: Union[str, Path, bytes],
        public_key_source: Union[str, Path, bytes, ed25519.Ed25519PublicKey]
    ) -> VerificationResult:
        """Verify a document's detached signature against a public key safely.

        Safely handles non-existent files, modified documents, incorrect keys,
        and malformed inputs without unhandled crashes.

        Args:
            document_path: Path to the original document file.
            signature_source: Path to the .sig file or raw signature bytes.
            public_key_source: Path to public key PEM, raw bytes, or Ed25519PublicKey object.

        Returns:
            VerificationResult: Contains boolean status and descriptive explanation.
        """
        # Validate caller-supplied types before constructing paths or loading keys.
        if not isinstance(document_path, (str, Path)):
            return VerificationResult(
                is_valid=False,
                message="Verification failed: Invalid document path.",
                details=f"Expected str or Path, got {type(document_path).__name__}"
            )
        if not isinstance(signature_source, (str, Path, bytes, bytearray)):
            return VerificationResult(
                is_valid=False,
                message="Verification failed: Invalid signature source type.",
                details=f"Expected path or bytes, got {type(signature_source).__name__}"
            )
        if not isinstance(
            public_key_source,
            (str, Path, bytes, bytearray, ed25519.Ed25519PublicKey)
        ):
            return VerificationResult(
                is_valid=False,
                message="Verification failed: Invalid public key source type.",
                details=f"Expected path, bytes, or Ed25519 public key, got {type(public_key_source).__name__}"
            )

        # 1. Read document bytes exactly as signed (binary mode).
        try:
            doc_path = Path(document_path)
            if not doc_path.is_file():
                return VerificationResult(
                    is_valid=False,
                    message="Verification failed: Document file does not exist.",
                    details=f"Path not found: {doc_path}"
                )
            with open(doc_path, "rb") as f:
                doc_bytes = f.read()
        except (OSError, ValueError, TypeError) as e:
            return VerificationResult(
                is_valid=False,
                message="Verification failed: Unable to read document file.",
                details=str(e)
            )

        # 2. Read signature bytes
        if isinstance(signature_source, (str, Path)):
            try:
                sig_path = Path(signature_source)
            except (TypeError, ValueError) as e:
                return VerificationResult(
                    is_valid=False,
                    message="Verification failed: Invalid signature path.",
                    details=str(e)
                )
            if not sig_path.is_file():
                return VerificationResult(
                    is_valid=False,
                    message="Verification failed: Signature file does not exist.",
                    details=f"Path not found: {sig_path}"
                )
            try:
                with open(sig_path, "rb") as f:
                    sig_bytes = f.read()
            except OSError as e:
                return VerificationResult(
                    is_valid=False,
                    message="Verification failed: Unable to read signature file.",
                    details=str(e)
                )
        elif isinstance(signature_source, (bytes, bytearray)):
            sig_bytes = bytes(signature_source)
        else:
            return VerificationResult(
                is_valid=False,
                message="Verification failed: Invalid signature source type.",
                details=f"Expected path or bytes, got {type(signature_source).__name__}"
            )

        if len(sig_bytes) != 64:
            return VerificationResult(
                is_valid=False,
                message=f"Verification failed: Malformed signature length ({len(sig_bytes)} bytes; Ed25519 requires exactly 64 bytes).",
                details="Signature length mismatch"
            )

        # 3. Load public key
        if isinstance(public_key_source, ed25519.Ed25519PublicKey):
            pub_key_obj = public_key_source
        else:
            try:
                if isinstance(public_key_source, bytearray):
                    public_key_source = bytes(public_key_source)
                pub_key_obj = KeyManager.load_public_key(public_key_source)
            except FileNotFoundError:
                return VerificationResult(
                    is_valid=False,
                    message="Verification failed: Public key file does not exist.",
                    details=str(public_key_source)
                )
            except KeyFormatError as e:
                return VerificationResult(
                    is_valid=False,
                    message=f"Verification failed: Malformed or invalid public key file.",
                    details=str(e)
                )
            except Exception as e:
                return VerificationResult(
                    is_valid=False,
                    message=f"Verification failed: Error loading public key.",
                    details=str(e)
                )

        # 4. Perform cryptographic verification
        valid = cls.verify_bytes(doc_bytes, sig_bytes, pub_key_obj)
        if valid:
            return VerificationResult(
                is_valid=True,
                message="Signature verification SUCCEEDED: The document is authentic and unmodified.",
                details="Cryptographic signature matches the document bytes and public key."
            )
        else:
            return VerificationResult(
                is_valid=False,
                message="Signature verification FAILED: Document modified or invalid signature/public key.",
                details="The mathematical verification failed under the provided public key."
            )
