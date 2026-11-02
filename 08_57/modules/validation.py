"""Input validation helpers.

Every problem caused by user input is reported with `InputError`. Its message is
written for normal users, so the UI can show it directly (no stack traces).
"""

from typing import Optional

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB is plenty for a college demo
ED25519_SIGNATURE_LENGTH = 64           # An Ed25519 signature is always 64 bytes


class InputError(Exception):
    """The user supplied missing, empty, malformed or unusable input."""


def require_present(data: Optional[object], label: str) -> None:
    """Raise InputError if a required input was not provided."""
    if data is None:
        raise InputError(f"{label} is missing. Please provide it before continuing.")


def validate_document(document: Optional[bytes]) -> bytes:
    """A document must exist, be non-empty and not be huge."""
    require_present(document, "The document")
    if len(document) == 0:
        raise InputError("The document is empty. An empty document cannot be signed or verified.")
    if len(document) > MAX_FILE_SIZE_BYTES:
        raise InputError("The document is larger than 10 MB, which this demo does not support.")
    return document


def validate_signature_bytes(signature: Optional[bytes]) -> bytes:
    """A signature file must contain exactly 64 raw bytes (Ed25519)."""
    require_present(signature, "The signature")
    if len(signature) != ED25519_SIGNATURE_LENGTH:
        raise InputError(
            f"The signature file has an invalid format: an Ed25519 signature must be exactly "
            f"{ED25519_SIGNATURE_LENGTH} bytes, but this file has {len(signature)} bytes. "
            f"Did you upload the wrong file?"
        )
    return signature


def validate_key_file_bytes(data: Optional[bytes], label: str) -> bytes:
    """A key file must exist, be non-empty and not be huge (real keys are tiny)."""
    require_present(data, label)
    if len(data) == 0:
        raise InputError(f"{label} is empty.")
    if len(data) > 100_000:
        raise InputError(f"{label} is far too large to be a key file.")
    return data
