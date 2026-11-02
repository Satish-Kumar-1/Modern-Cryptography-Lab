"""Loading documents.

Documents are always handled as raw bytes. We never decode them to text, strip
whitespace or normalize line endings, because changing even one byte would
change the signature result.
"""

import hashlib
from pathlib import Path
from typing import Union

from modules.validation import validate_document
from utils.file_utils import read_file_bytes, read_upload


def load_document_from_path(path: Union[str, Path]) -> bytes:
    return validate_document(read_file_bytes(path))


def load_document_from_upload(uploaded_file) -> bytes:
    return validate_document(read_upload(uploaded_file, "The document"))


def describe_document(document: bytes) -> dict:
    """Basic facts for display. The SHA-256 is only informational; it is NOT the signature."""
    return {"size_bytes": len(document), "sha256": hashlib.sha256(document).hexdigest()}
