"""Creating Ed25519 signatures."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.validation import require_present, validate_document


def sign_document(document: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign the exact document bytes and return the 64-byte signature.

    Ed25519 hashes the message internally (with SHA-512), so we pass the whole
    document and do NOT hash it ourselves. Signing is NOT encryption: the document
    stays readable, the signature is just extra proof attached next to it.
    """
    validate_document(document)
    require_present(private_key, "The private key")
    return private_key.sign(document)
