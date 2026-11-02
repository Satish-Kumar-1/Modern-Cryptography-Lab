"""RSA-PSS signatures, SPKI fingerprints, RSA-OAEP key wrapping and AES-GCM."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.DIGEST_LENGTH,
)
OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def save_private_key(private_key: rsa.RSAPrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)  # private keys should be owner-readable only
    except OSError:
        pass


def save_public_key(public_key: rsa.RSAPublicKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_key_pem(public_key).encode("ascii"))


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem: str | bytes) -> rsa.RSAPublicKey:
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    return serialization.load_pem_public_key(pem)


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 fingerprint of the SubjectPublicKeyInfo (SPKI) DER encoding."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(data, PSS_PADDING, hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, PSS_PADDING, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


# --- Confidentiality: hybrid encryption (fresh AES key per message, wrapped for the recipient)

def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def wrap_key(recipient_public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    return recipient_public_key.encrypt(aes_key, OAEP_PADDING)


def unwrap_key(recipient_private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return recipient_private_key.decrypt(wrapped, OAEP_PADDING)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_aes_gcm(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)