"""Ed25519 key generation, serialization (PEM) and loading.

Key formats used:
  * Private key: PKCS#8 PEM. Optionally encrypted with a password.
  * Public key : SubjectPublicKeyInfo PEM (the standard "-----BEGIN PUBLIC KEY-----" format).
The password is typed by the user, used once to encrypt/decrypt, and never stored or hardcoded.
"""

from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from modules.validation import InputError, validate_key_file_bytes
from utils.file_utils import read_file_bytes, write_file_bytes


def generate_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Create a new key pair. The library draws randomness from the operating
    system's cryptographically secure random number generator."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_from_private(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    """The public key is mathematically derived from the private key."""
    return private_key.public_key()


def private_key_to_pem(private_key: Ed25519PrivateKey, password: Optional[str] = None) -> bytes:
    """Serialize a private key. With a password, the PEM is encrypted; without one, it is NOT."""
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: Optional[bytes], password: Optional[str] = None) -> Ed25519PrivateKey:
    """Parse a PEM private key. Raises InputError with a clear message on any problem."""
    pem_data = validate_key_file_bytes(pem_data, "The private key file")
    is_encrypted = b"ENCRYPTED" in pem_data
    if is_encrypted and not password:
        raise InputError("This private key is password-protected. Please enter its password.")
    try:
        key = serialization.load_pem_private_key(
            pem_data, password=password.encode("utf-8") if (is_encrypted and password) else None
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        if is_encrypted:
            raise InputError("Could not decrypt the private key. The password is probably incorrect.") from exc
        raise InputError("The private key file is not a valid PEM private key.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise InputError("This is a valid private key, but not an Ed25519 key (e.g. it may be RSA).")
    return key


def load_public_key(pem_data: Optional[bytes]) -> Ed25519PublicKey:
    """Parse a PEM public key. Raises InputError with a clear message on any problem."""
    pem_data = validate_key_file_bytes(pem_data, "The public key file")
    try:
        key = serialization.load_pem_public_key(pem_data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise InputError("The public key file is not a valid PEM public key.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise InputError("This is a valid public key, but not an Ed25519 key (e.g. it may be RSA).")
    return key


# ---- Convenience wrappers for saving / loading key files on disk -------------------

def save_private_key(path: Union[str, Path], private_key: Ed25519PrivateKey, password: Optional[str] = None) -> None:
    write_file_bytes(path, private_key_to_pem(private_key, password))


def save_public_key(path: Union[str, Path], public_key: Ed25519PublicKey) -> None:
    write_file_bytes(path, public_key_to_pem(public_key))


def load_private_key_file(path: Union[str, Path], password: Optional[str] = None) -> Ed25519PrivateKey:
    return load_private_key(read_file_bytes(path), password)


def load_public_key_file(path: Union[str, Path]) -> Ed25519PublicKey:
    return load_public_key(read_file_bytes(path))
