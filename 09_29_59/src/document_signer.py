"""Document Signer Module for Ed25519 Detached Digital Signatures.

Person 1: Cryptographic Core & Key Management Lead.

This module provides functions to sign arbitrary document files and raw byte
streams using Ed25519 private keys. Crucially:
1. It signs exact binary bytes without normalising line endings or whitespace.
2. It generates detached digital signatures (64 bytes), leaving the original
   document untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.key_manager import (
    CryptographicError,
    KeyManager,
)


class SigningError(CryptographicError):
    """Raised when document signing fails."""
    pass


class DocumentSigner:
    """Handles detached digital signing of files and bytes using Ed25519."""

    @staticmethod
    def sign_bytes(
        data: bytes,
        private_key: ed25519.Ed25519PrivateKey
    ) -> bytes:
        """Sign an exact sequence of bytes using an Ed25519 private key.

        Args:
            data: Exact byte payload to sign.
            private_key: Ed25519 private key instance.

        Returns:
            bytes: Exactly 64 bytes representing the Ed25519 digital signature.

        Raises:
            SigningError: If signing fails.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes or bytearray.")
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("Private key must be an instance of Ed25519PrivateKey.")

        try:
            signature = private_key.sign(bytes(data))
            return signature
        except Exception as e:
            raise SigningError(f"Failed to generate Ed25519 signature: {e}") from e

    @classmethod
    def sign_document(
        cls,
        document_path: Union[str, Path],
        private_key: Union[ed25519.Ed25519PrivateKey, str, Path],
        signature_output_path: Optional[Union[str, Path]] = None,
        password: Optional[str] = None
    ) -> bytes:
        """Sign the exact bytes of a document file and optionally write a detached signature file.

        Args:
            document_path: Path to the target document to be signed.
            private_key: Either an active Ed25519PrivateKey object or a file path to a private key PEM.
            signature_output_path: Optional path where the detached signature (.sig) should be saved.
                                   If None and a file path is desired, appends '.sig' to the document path.
            password: Optional passphrase if loading an encrypted private key from disk.

        Returns:
            bytes: The 64-byte Ed25519 signature.

        Raises:
            FileNotFoundError: If the document or key file does not exist.
            SigningError: If the signing process fails.
        """
        doc_file = Path(document_path).resolve()
        if not doc_file.is_file():
            raise FileNotFoundError(f"Document file not found: {doc_file}")

        # Read exact bytes in binary mode to preserve whitespace & encoding
        with open(doc_file, "rb") as f:
            document_bytes = f.read()

        # Resolve private key
        if isinstance(private_key, (str, Path)):
            priv_key_obj = KeyManager.load_private_key(private_key, password=password)
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            priv_key_obj = private_key
        else:
            raise TypeError("private_key must be an Ed25519PrivateKey or path to a key file.")

        signature = cls.sign_bytes(document_bytes, priv_key_obj)

        # Write detached signature file if specified
        if signature_output_path is not None:
            sig_file = Path(signature_output_path).resolve()
            sig_file.parent.mkdir(parents=True, exist_ok=True)
            with open(sig_file, "wb") as f:
                f.write(signature)

        return signature
