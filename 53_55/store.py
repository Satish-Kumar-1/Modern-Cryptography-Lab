"""On-disk keys, trust store, out-of-band pins, inboxes and quarantine"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

from . import crypto

ROOT = Path(os.environ.get("SECMSG_HOME", Path(__file__).resolve().parent.parent))
KEYS_DIR = ROOT / "keys"
DATA_DIR = ROOT / "data"
SAMPLES_DIR = ROOT / "samples"
TRUST_PATH = DATA_DIR / "trust_store.json"
PINS_PATH = DATA_DIR / "pinned_fingerprints.json"
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")


def _read_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _private_path(name: str) -> Path:
    return KEYS_DIR / f"{name.lower()}_private.pem"


def _public_path(name: str) -> Path:
    return KEYS_DIR / f"{name.lower()}_public.pem"


def inbox_path(name: str) -> Path:
    return DATA_DIR / f"inbox_{name.lower()}.jsonl"


def _quarantine_path(name: str) -> Path:
    return DATA_DIR / f"quarantine_{name.lower()}.jsonl"


def _seen_path(name: str) -> Path:
    return DATA_DIR / f"seen_{name.lower()}.json"


# ---------------------------------------------------------------- sample files + activity log

def log_event(kind: str, detail: str, result: dict | None = None) -> None:
    """Append one line (plus its verdict) to samples/experiment_log.txt."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = f"[{stamp}] {kind:<16} {detail}\n"
    if result is not None:
        verdict = "ACCEPTED" if result["valid"] else "REJECTED"
        text += f"{'':22}-> {verdict} [{result['stage']}]: {result['reason']}\n"
    with (SAMPLES_DIR / "experiment_log.txt").open("a", encoding="utf-8") as handle:
        handle.write(text)


def save_sample(payload: dict) -> None:
    """Keep the newest plaintext and newest encrypted message as sample files."""
    name = "sample_encrypted_message.json" if payload.get("encrypted") else "sample_signed_message.json"
    _write_json(SAMPLES_DIR / name, payload)


def refresh_public_keys_sample() -> None:
    _write_json(SAMPLES_DIR / "public_keys.json", load_trust_store())


# ---------------------------------------------------------------- users

def list_users() -> list[str]:
    return sorted(load_pins())


def canonical_name(name: str) -> str | None:
    """Case-insensitive lookup; returns the registered spelling or None."""
    for user in list_users():
        if user.lower() == name.strip().lower():
            return user
    return None


def create_user(name: str) -> str:
    """Generate a key pair for a new identity, register it, return the fingerprint."""
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("Names must start with a letter and use only letters, digits, - or _ (max 32).")
    if canonical_name(name):
        raise ValueError(f"User '{name}' already exists.")
    private_key, public_key = crypto.generate_rsa_keypair()
    crypto.save_private_key(private_key, _private_path(name))
    crypto.save_public_key(public_key, _public_path(name))
    fp = crypto.fingerprint(public_key)
    trust = load_trust_store()
    trust[name] = {"fingerprint": fp, "public_key_pem": crypto.public_key_pem(public_key)}
    save_trust_store(trust)
    pins = load_pins()
    pins[name] = fp
    _write_json(PINS_PATH, pins)
    refresh_public_keys_sample()
    log_event("USER CREATED", f"{name}  fingerprint {fp}")
    return fp


def remove_user(name: str) -> int:
    """Delete a user's keys, mailbox, trust entry and pin. Also purges their old messages
    from everyone else's inbox/quarantine. Returns how many other messages were purged."""
    canon = canonical_name(name)
    if canon is None:
        raise ValueError(f"User '{name}' does not exist.")
    others = [u for u in list_users() if u != canon]
    for path in (_private_path(canon), _public_path(canon), inbox_path(canon),
                 _quarantine_path(canon), _seen_path(canon)):
        path.unlink(missing_ok=True)
    trust, pins = load_trust_store(), load_pins()
    trust.pop(canon, None)
    pins.pop(canon, None)
    save_trust_store(trust)
    _write_json(PINS_PATH, pins)
    purged = 0
    for other in others:
        inbox = read_inbox(other)
        kept = [m for m in inbox if m.get("from") != canon]
        quarantine = read_quarantine(other)
        kept_q = [q for q in quarantine if q["payload"].get("from") != canon]
        purged += (len(inbox) - len(kept)) + (len(quarantine) - len(kept_q))
        _rewrite(inbox_path(other), kept)
        _rewrite(_quarantine_path(other), kept_q)
    refresh_public_keys_sample()
    log_event("USER REMOVED", f"{canon}  ({purged} related message(s) purged)")
    return purged


def _rewrite(path: Path, records: list[dict]) -> None:
    if not path.exists():
        return
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def wipe_everything() -> None:
    for folder in (KEYS_DIR, DATA_DIR):
        shutil.rmtree(folder, ignore_errors=True)


# ---------------------------------------------------------------- trust + pins

def load_trust_store() -> dict:
    return _read_json(TRUST_PATH, {})


def save_trust_store(trust: dict) -> None:
    _write_json(TRUST_PATH, trust)


def load_pins() -> dict[str, str]:
    return _read_json(PINS_PATH, {})


def trusted_fingerprint(identity: str) -> str | None:
    return load_pins().get(identity)


def trusted_public_key(identity: str, trust: dict | None = None):
    trust = load_trust_store() if trust is None else trust
    return crypto.public_key_from_pem(trust[identity]["public_key_pem"])


def private_key_for(name: str):
    return crypto.load_private_key(_private_path(name))


def public_key_for(name: str):
    return crypto.load_public_key(_public_path(name))


# ---------------------------------------------------------------- mailboxes

def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _read_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def append_inbox(recipient: str, payload: dict) -> None:
    _append(inbox_path(recipient), payload)


def read_inbox(recipient: str) -> list[dict]:
    return _read_lines(inbox_path(recipient))


def append_quarantine(recipient: str, payload: dict, reason: str) -> None:
    _append(_quarantine_path(recipient), {"reason": reason, "payload": payload})


def read_quarantine(recipient: str) -> list[dict]:
    return _read_lines(_quarantine_path(recipient))


def load_seen_ids(recipient: str) -> set[str]:
    return set(_read_json(_seen_path(recipient), []))


def save_seen_ids(recipient: str, seen: set[str]) -> None:
    _write_json(_seen_path(recipient), sorted(seen))