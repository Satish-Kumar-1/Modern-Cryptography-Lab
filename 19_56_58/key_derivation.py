"""Key derivation module using HKDF.

Provides key derivation functions to expand raw shared secrets into
cryptographically strong symmetric encryption keys.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(
    shared_secret: bytes,
    salt: bytes | None = None,
    info: bytes = b"dh-mitm-project-v1",
) -> bytes:
    """Derive a 32-byte symmetric key from a shared secret using HKDF-SHA256.

    Args:
        shared_secret: The raw input key material (e.g. from Diffie-Hellman).
        salt: Optional salt value. If None, HKDF defaults to a string of zeros.
        info: Optional context and application-specific information string.

    Returns:
        bytes: A cryptographically strong 32-byte key suitable for AES-256.

    Raises:
        TypeError: If inputs are of incorrect types.
    """
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise TypeError("shared_secret must be a bytes-like object")
    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes, bytearray, or None")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("info must be a bytes-like object")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)

