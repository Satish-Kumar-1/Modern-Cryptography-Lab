"""Verifying Ed25519 signatures. This function never raises: it always returns a result."""

import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modules.validation import InputError, require_present, validate_document, validate_signature_bytes

logger = logging.getLogger(__name__)

VALID, INVALID, ERROR = "valid", "invalid", "error"


@dataclass
class VerificationResult:
    status: str                  # "valid", "invalid" or "error" (could not be checked)
    message: str                 # user-friendly explanation
    technical_detail: str = ""   # only for debugging; the UI shows it only in debug mode

    @property
    def is_valid(self) -> bool:
        return self.status == VALID


def verify_document(document: bytes, signature: bytes, public_key: Ed25519PublicKey) -> VerificationResult:
    """Check `signature` against the exact `document` bytes using `public_key`."""
    try:
        validate_document(document)
        validate_signature_bytes(signature)
        require_present(public_key, "The public key")
    except InputError as exc:
        return VerificationResult(ERROR, str(exc))

    try:
        # Returns None on success and raises InvalidSignature on ANY mismatch
        # (changed document, changed signature, or a different public key).
        public_key.verify(signature, document)
    except InvalidSignature:
        return VerificationResult(
            INVALID,
            "The signature does NOT match. Either the document was changed, the signature was "
            "changed or damaged, or this is not the public key that matches the signing key.",
        )
    except Exception as exc:  # never treat an unexpected problem as success
        logger.exception("Unexpected error during verification")
        return VerificationResult(ERROR, "Verification could not be completed because of an unexpected error.",
                                  technical_detail=repr(exc))

    return VerificationResult(
        VALID,
        "The signature is mathematically valid for this exact document under this public key. "
        "The document has not been changed since it was signed. This alone does not prove WHO owns "
        "the key; compare the key's fingerprint with a trusted one for that.",
    )
