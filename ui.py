"""Small terminal-formatting helpers: aligned key/value rows, wrapped text, tables, colour"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from datetime import datetime, timezone

try:  # avoid UnicodeEncodeError on legacy Windows consoles
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

WIDTH = max(60, min(shutil.get_terminal_size((80, 24)).columns, 88))
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if USE_COLOR and os.name == "nt":
    os.system("")  # enables ANSI escape codes in Windows terminals

_COLORS = {
    "[ACCEPTED]": "1;32", "[REJECTED]": "1;31", "VALID": "32", "INVALID": "31",
    "attack SUCCEEDED": "1;31", "attack blocked": "32", "Accepted": "32",
    "REJECTED": "31", "ACCEPTED": "32", "MISMATCH": "1;31", "OK ": "32",
}


def colorize(text: str) -> str:
    if not USE_COLOR:
        return text
    for word, code in sorted(_COLORS.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(word, f"\033[{code}m{word}\033[0m")
    return text


def show(text: str = "") -> None:
    print(colorize(text))


def rule(char: str = "-") -> str:
    return char * WIDTH


def fmt_header(text: str) -> str:
    return f"\n{rule('=')}\n {text.upper()}\n{rule('=')}"


def fmt_section(text: str) -> str:
    return f"\n{text}\n{rule('-')}"


def fmt_kv(label: str, value, indent: int = 2, width: int = 16) -> str:
    prefix = " " * indent + f"{label:<{width}}: "
    pad = " " * len(prefix)
    lines = textwrap.wrap(str(value), max(30, WIDTH - len(prefix)),
                          break_long_words=False, break_on_hyphens=False) or [""]
    return "\n".join((prefix if i == 0 else pad) + line for i, line in enumerate(lines))


def fmt_para(text: str, label: str = "", indent: int = 2) -> str:
    first = " " * indent + (f"{label} " if label else "")
    return textwrap.fill(str(text), WIDTH, initial_indent=first,
                         subsequent_indent=" " * len(first), break_long_words=False)


def fmt_table(headers: tuple[str, ...], rows: list[tuple[str, ...]], indent: int = 2) -> str:
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    def line(cells):
        return " " * indent + "  ".join(f"{str(c):<{w}}" for c, w in zip(cells, widths)).rstrip()
    sep = " " * indent + "  ".join("-" * w for w in widths)
    return "\n".join([line(headers), sep, *[line(r) for r in rows]])


def badge(valid: bool) -> str:
    return "[ACCEPTED]" if valid else "[REJECTED]"


def fmt_ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        return str(iso)


def short_fp(fp: str) -> str:
    parts = fp.split(":")
    return fp if len(parts) < 8 else ":".join(parts[:4]) + ":...:" + ":".join(parts[-3:])


def clip(text: str, n: int = 60) -> str:
    text = str(text).replace("\n", " ")
    return text if len(text) <= n else text[: n - 3] + "..."