"""Key Manager Module for Ed25519 Digital Signatures.

Person 1: Cryptographic Core & Key Management Lead.

This module provides cryptographically secure generation, serialization,
storage, and loading of Ed25519 (RFC 8032) asymmetric key pairs using the
standard Python `cryptography` library.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class CryptographicError(Exception):
    """Base exception for cryptographic operations."""
    pass


class KeyManagementError(CryptographicError):
    """Raised when key operations (generation, import, export) fail."""
    pass


class KeyFormatError(KeyManagementError):
    """Raised when a key is corrupted, malformed, or has an unexpected format."""
    pass


class PassphraseError(KeyManagementError):
    """Raised when passphrase operations fail."""
    pass


class InvalidPassphraseError(PassphraseError):
    """Raised when an incorrect passphrase is provided for an encrypted private key."""
    pass


class KeyManager:
    """Manages Ed25519 private and public keys."""

    @staticmethod
    def generate_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate a cryptographically secure Ed25519 private/public key pair.

        Uses the OS cryptographic random source (e.g., CryptGenRandom / getrandom)
        via the established cryptography library.

        Returns:
            Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]: Generated key pair.
        """
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            raise KeyManagementError(f"Failed to generate Ed25519 key pair: {e}") from e

    @staticmethod
    def save_private_key(
        private_key: ed25519.Ed25519PrivateKey,
        file_path: Union[str, Path],
        password: Optional[str] = None
    ) -> Path:
        """Serialize and save an Ed25519 private key to disk in PKCS#8 PEM format.

        Security Note:
            Private keys must be protected and never committed to version control.
            Optionally encrypts the key at rest using BestAvailableEncryption (AES-256-CBC).

        Args:
            private_key: The Ed25519 private key object.
            file_path: Destination path where the private key PEM should be saved.
            password: Optional passphrase to encrypt the private key at rest.

        Returns:
            Path: Absolute path to the saved private key file.
        """
        target_path = Path(file_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if password:
            encryption_algo = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption_algo = serialization.NoEncryption()

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo,
        )

        # Write securely
        with open(target_path, "wb") as f:
            f.write(pem_data)

        # Restrict permissions on POSIX systems (chmod 0600)
        try:
            if hasattr(os, "chmod") and os.name == "posix":
                os.chmod(target_path, 0o600)
        except OSError:
            pass

        return target_path

    @staticmethod
    def save_public_key(
        public_key: ed25519.Ed25519PublicKey,
        file_path: Union[str, Path]
    ) -> Path:
        """Serialize and save an Ed25519 public key to disk in SubjectPublicKeyInfo (SPKI) PEM format.

        This public key file can be distributed to verifiers.

        Args:
            public_key: The Ed25519 public key object.
            file_path: Destination path where the public key PEM should be saved.

        Returns:
            Path: Absolute path to the saved public key file.
        """
        target_path = Path(file_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(target_path, "wb") as f:
            f.write(pem_data)

        return target_path

    @staticmethod
    def load_private_key(
        source: Union[str, Path, bytes],
        password: Optional[str] = None
    ) -> ed25519.Ed25519PrivateKey:
        """Load an Ed25519 private key from a file path or raw PEM bytes.

        Args:
            source: File path (str or Path) or raw PEM bytes.
            password: Passphrase if the private key is encrypted.

        Returns:
            ed25519.Ed25519PrivateKey: Loaded private key.

        Raises:
            FileNotFoundError: If the key file does not exist.
            InvalidPassphraseError: If the passphrase is incorrect or missing.
            KeyFormatError: If the key is corrupted or not an Ed25519 private key.
        """
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.is_file():
                raise FileNotFoundError(f"Private key file not found: {path}")
            with open(path, "rb") as f:
                data = f.read()
        elif isinstance(source, bytes):
            data = source
        else:
            raise TypeError("Source must be a file path or bytes.")

        pass_bytes = password.encode("utf-8") if password else None

        try:
            key = serialization.load_pem_private_key(data, password=pass_bytes)
        except TypeError as e:
            # Often raised when a password is required but None was provided
            raise PassphraseError(f"Password required or invalid type for private key: {e}") from e
        except ValueError as e:
            # Raised if password was incorrect or PEM data was malformed
            error_msg = str(e).lower()
            if "bad decrypt" in error_msg or "password" in error_msg:
                raise InvalidPassphraseError("Incorrect passphrase supplied for private key.") from e
            raise KeyFormatError(f"Malformed or invalid private key data: {e}") from e
        except UnsupportedAlgorithm as e:
            raise KeyFormatError(f"Unsupported key algorithm: {e}") from e
        except Exception as e:
            raise KeyFormatError(f"Failed to load private key: {e}") from e

        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise KeyFormatError(f"Expected Ed25519PrivateKey, got {type(key).__name__}")

        return key

    @staticmethod
    def load_public_key(
        source: Union[str, Path, bytes]
    ) -> ed25519.Ed25519PublicKey:
        """Load an Ed25519 public key from a file path, PEM bytes, or raw 32-byte representation.

        Args:
            source: File path (str or Path), PEM bytes, or raw 32-byte public key.

        Returns:
            ed25519.Ed25519PublicKey: Loaded public key.

        Raises:
            FileNotFoundError: If the public key file does not exist.
            KeyFormatError: If the key is malformed or invalid.
        """
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.is_file():
                raise FileNotFoundError(f"Public key file not found: {path}")
            with open(path, "rb") as f:
                data = f.read()
        elif isinstance(source, bytes):
            data = source
        else:
            raise TypeError("Source must be a file path or bytes.")

        # If exactly 32 bytes, try loading as raw Ed25519 public key
        if len(data) == 32:
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(data)
            except Exception as e:
                raise KeyFormatError(f"Invalid 32-byte Ed25519 public key: {e}") from e

        # Otherwise try loading as standard PEM (SPKI)
        try:
            key = serialization.load_pem_public_key(data)
        except Exception as e:
            raise KeyFormatError(f"Malformed or invalid public key file: {e}") from e

        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise KeyFormatError(f"Expected Ed25519PublicKey, got {type(key).__name__}")

        return key

    @staticmethod
    def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
        """Export public key as a PEM-formatted string (SPKI)."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @staticmethod
    def export_public_key_raw(public_key: ed25519.Ed25519PublicKey) -> bytes:
        """Export public key as 32 raw bytes."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
