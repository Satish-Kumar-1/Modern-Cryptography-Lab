"""X25519 key agreement implementation.

Provides functions to generate X25519 key pairs, derive shared secrets,
and securely compare shared secrets using constant-time comparison.
"""

import hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def generate_key_pair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 private key and its corresponding public key.

    Returns:
        tuple[X25519PrivateKey, X25519PublicKey]: A tuple containing the
        generated private key and its associated public key.
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Derive a shared secret using X25519 key agreement.

    Args:
        private_key: Local party's X25519 private key.
        peer_public_key: Peer's X25519 public key.

    Returns:
        bytes: The 32-byte raw shared secret.

    Raises:
        TypeError: If keys are not valid X25519 key instances.
        Exception: If key agreement fails.
    """
    if not isinstance(private_key, X25519PrivateKey):
        raise TypeError("private_key must be an instance of X25519PrivateKey")
    if not isinstance(peer_public_key, X25519PublicKey):
        raise TypeError("peer_public_key must be an instance of X25519PublicKey")

    return private_key.exchange(peer_public_key)


def verify_shared_secret(secret_a: bytes, secret_b: bytes) -> bool:
    """Compare two shared secrets using constant-time comparison.

    Args:
        secret_a: First shared secret in bytes.
        secret_b: Second shared secret in bytes.

    Returns:
        bool: True if secrets match exactly, False otherwise.

    Raises:
        TypeError: If either secret is not a bytes-like object.
    """
    if not isinstance(secret_a, (bytes, bytearray)):
        raise TypeError("secret_a must be bytes or bytearray")
    if not isinstance(secret_b, (bytes, bytearray)):
        raise TypeError("secret_b must be bytes or bytearray")

    return hmac.compare_digest(secret_a, secret_b)

