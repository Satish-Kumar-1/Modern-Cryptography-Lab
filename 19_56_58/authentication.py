"""Authentication module using Ed25519 digital signatures.

Provides functions to generate signing key pairs, construct canonical
context-bound messages, sign ephemeral X25519 public keys, and verify signatures
against trusted public keys to prevent man-in-the-middle and misbinding attacks.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

DEFAULT_PROTOCOL_ID: bytes = b"dh-mitm-v2"


def generate_signing_key_pair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 private key and its corresponding public key.

    Returns:
        tuple[Ed25519PrivateKey, Ed25519PublicKey]: A tuple containing the
        generated Ed25519 private key and public key.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def build_canonical_message(
    exchange_public_key: X25519PublicKey,
    sender_id: bytes | str,
    recipient_id: bytes | str,
    protocol_id: bytes | str = DEFAULT_PROTOCOL_ID,
) -> bytes:
    """Construct an unambiguous, length-prefixed canonical byte string.

    Binds:
      - Fixed protocol identifier / version.
      - Sender identity.
      - Intended recipient identity.
      - 32-byte raw X25519 public key.

    Encoding format:
      [2-byte big-endian len(protocol_id)] + protocol_id +
      [2-byte big-endian len(sender_id)]   + sender_id +
      [2-byte big-endian len(recipient_id)] + recipient_id +
      [32-byte raw exchange_public_key bytes]

    Raises:
        TypeError: If arguments are of incorrect types.
    """
    if not isinstance(exchange_public_key, X25519PublicKey):
        raise TypeError("exchange_public_key must be an instance of X25519PublicKey")

    sender_bytes = (
        sender_id.encode("utf-8") if isinstance(sender_id, str) else sender_id
    )
    recipient_bytes = (
        recipient_id.encode("utf-8") if isinstance(recipient_id, str) else recipient_id
    )
    protocol_bytes = (
        protocol_id.encode("utf-8") if isinstance(protocol_id, str) else protocol_id
    )

    if not isinstance(sender_bytes, (bytes, bytearray)):
        raise TypeError("sender_id must be a bytes-like object or str")
    if not isinstance(recipient_bytes, (bytes, bytearray)):
        raise TypeError("recipient_id must be a bytes-like object or str")
    if not isinstance(protocol_bytes, (bytes, bytearray)):
        raise TypeError("protocol_id must be a bytes-like object or str")

    raw_public_bytes = exchange_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        len(protocol_bytes).to_bytes(2, "big")
        + bytes(protocol_bytes)
        + len(sender_bytes).to_bytes(2, "big")
        + bytes(sender_bytes)
        + len(recipient_bytes).to_bytes(2, "big")
        + bytes(recipient_bytes)
        + raw_public_bytes
    )


def sign_public_key(
    signing_private_key: Ed25519PrivateKey,
    exchange_public_key: X25519PublicKey,
    sender_id: bytes | str,
    recipient_id: bytes | str,
    protocol_id: bytes | str = DEFAULT_PROTOCOL_ID,
) -> bytes:
    """Sign an X25519 public key bound to sender, recipient, and protocol ID.

    Args:
        signing_private_key: The Ed25519 private key used to sign.
        exchange_public_key: The X25519 public key to be signed.
        sender_id: The identity of the sender.
        recipient_id: The intended recipient identity.
        protocol_id: Protocol identifier / version string.

    Returns:
        bytes: The 64-byte Ed25519 digital signature.

    Raises:
        TypeError: If keys or parameters are of incorrect types.
    """
    if not isinstance(signing_private_key, Ed25519PrivateKey):
        raise TypeError("signing_private_key must be an instance of Ed25519PrivateKey")

    canonical_message = build_canonical_message(
        exchange_public_key=exchange_public_key,
        sender_id=sender_id,
        recipient_id=recipient_id,
        protocol_id=protocol_id,
    )
    return signing_private_key.sign(canonical_message)


def verify_public_key_signature(
    trusted_signing_public_key: Ed25519PublicKey,
    exchange_public_key: X25519PublicKey,
    signature: bytes,
    sender_id: bytes | str,
    recipient_id: bytes | str,
    protocol_id: bytes | str = DEFAULT_PROTOCOL_ID,
) -> bool:
    """Verify an Ed25519 signature binding an X25519 key to sender, recipient, and protocol.

    Args:
        trusted_signing_public_key: The trusted Ed25519 public key of the sender.
        exchange_public_key: The X25519 public key whose authenticity is being verified.
        signature: The digital signature bytes to verify.
        sender_id: The expected sender identity.
        recipient_id: The expected recipient identity.
        protocol_id: The expected protocol identifier / version string.

    Returns:
        bool: True if verification succeeds, False if InvalidSignature is raised.

    Raises:
        TypeError: If arguments are of incorrect types.
    """
    if not isinstance(trusted_signing_public_key, Ed25519PublicKey):
        raise TypeError(
            "trusted_signing_public_key must be an instance of Ed25519PublicKey"
        )
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be a bytes-like object")

    canonical_message = build_canonical_message(
        exchange_public_key=exchange_public_key,
        sender_id=sender_id,
        recipient_id=recipient_id,
        protocol_id=protocol_id,
    )

    try:
        trusted_signing_public_key.verify(signature, canonical_message)
        return True
    except InvalidSignature:
        return False
