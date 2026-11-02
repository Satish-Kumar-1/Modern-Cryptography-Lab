"""Reading and writing files, turning OS-level errors into friendly InputErrors."""

from pathlib import Path
from typing import Union

from modules.validation import InputError, MAX_FILE_SIZE_BYTES, require_present


def read_file_bytes(path: Union[str, Path]) -> bytes:
    """Read a file in binary mode so the bytes are never altered (no newline or encoding changes)."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            raise InputError(f"'{path.name}' is larger than 10 MB, which this demo does not support.")
        return path.read_bytes()
    except FileNotFoundError:
        raise InputError(f"The file '{path.name}' was not found.") from None
    except OSError as exc:
        raise InputError(f"The file '{path.name}' could not be read.") from exc


def write_file_bytes(path: Union[str, Path], data: bytes) -> None:
    """Write bytes to a file (binary mode)."""
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        raise InputError(f"The file '{Path(path).name}' could not be written.") from exc


def read_upload(uploaded_file, label: str) -> bytes:
    """Get the exact bytes of a Streamlit upload (any object with .getvalue())."""
    require_present(uploaded_file, label)
    try:
        return uploaded_file.getvalue()
    except Exception as exc:  # unreadable upload
        raise InputError(f"{label} could not be read.") from exc
