"""Authenticated symmetric encryption module using AES-256-GCM.

Provides functions to encrypt and decrypt messages with authenticated
confidentiality and integrity protection.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM with a random 12-byte nonce.

    Args:
        key: A 32-byte AES-256 key.
        plaintext: The plaintext data in bytes to encrypt.

    Returns:
        tuple[bytes, bytes]: A tuple of (nonce, ciphertext), where ciphertext
        includes the 16-byte authentication tag.

    Raises:
        TypeError: If key or plaintext is not a bytes-like object.
        ValueError: If key is not exactly 32 bytes.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be a bytes-like object")
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be a bytes-like object")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate ciphertext using AES-256-GCM.

    Args:
        key: A 32-byte AES-256 key.
        nonce: The 12-byte nonce used during encryption.
        ciphertext: The ciphertext bytes including the authentication tag.

    Returns:
        bytes: The decrypted plaintext bytes.

    Raises:
        TypeError: If key, nonce, or ciphertext is not a bytes-like object.
        ValueError: If key is not exactly 32 bytes.
        cryptography.exceptions.InvalidTag: If the authentication tag verification fails.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be a bytes-like object")
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("nonce must be a bytes-like object")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be a bytes-like object")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

