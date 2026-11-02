"""Signed (and optionally encrypted) message envelope, verification and delivery"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone

from . import crypto, store

MAX_AGE_SECONDS = 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
SIGNED_FIELDS = ("id", "timestamp", "from", "to", "encrypted", "wrapped_key", "body")


def canonical_bytes(payload: dict) -> bytes:
    """Exact signed content: canonical JSON of every field except the signature."""
    body = {k: payload[k] for k in SIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(message_id: str, sender: str, recipient: str) -> bytes:
    """Bind the ciphertext to its envelope so it can't be moved to another message."""
    return f"{message_id}|{sender}|{recipient}".encode("utf-8")


def create_signed_message(
    sender: str,
    recipient: str,
    text: str,
    *,
    encrypt: bool = False,
    message_id: str | None = None,
    timestamp: str | None = None,
    signer: str | None = None,
) -> dict:
    """Build a signed envelope. `signer` lets an attacker sign while claiming `sender`."""
    message_id = message_id or str(uuid.uuid4())
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    body, wrapped = text, ""
    if encrypt:
        aes_key = crypto.generate_aes_key()  # fresh key per message
        blob = crypto.encrypt_aes_gcm(aes_key, text.encode("utf-8"), _aad(message_id, sender, recipient))
        body = base64.b64encode(blob).decode("ascii")
        wrapped = base64.b64encode(crypto.wrap_key(store.trusted_public_key(recipient), aes_key)).decode("ascii")
    payload = {
        "id": message_id,
        "timestamp": timestamp,
        "from": sender,
        "to": recipient,
        "encrypted": encrypt,
        "wrapped_key": wrapped,
        "body": body,
    }
    sig = crypto.sign(store.private_key_for(signer or sender), canonical_bytes(payload))
    payload["signature"] = base64.b64encode(sig).decode("ascii")
    return payload


def decrypt_body(payload: dict, reader: str) -> str:
    """Decrypt with `reader`'s private key. Raises if reader is not the intended recipient."""
    if not payload.get("encrypted"):
        return payload["body"]
    aes_key = crypto.unwrap_key(store.private_key_for(reader), base64.b64decode(payload["wrapped_key"]))
    blob = base64.b64decode(payload["body"])
    aad = _aad(payload["id"], payload["from"], payload["to"])
    return crypto.decrypt_aes_gcm(aes_key, blob, aad).decode("utf-8")


def try_decrypt_as(payload: dict, reader: str) -> tuple[bool, str]:
    try:
        return True, decrypt_body(payload, reader)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: could not decrypt as {reader}"


def verify_message(
    payload: dict,
    *,
    reader: str | None = None,
    check_replay: bool = True,
    pin_fingerprints: bool = True,
    trust: dict | None = None,
    pins: dict | None = None,
    seen: set | None = None,
    max_age: float = MAX_AGE_SECONDS,
    decrypt: bool = True,
) -> dict:
    """Full receive pipeline.

    trust/pins/seen can be passed in-memory so experiments never touch real data.
    If `seen` is None the recipient's on-disk replay cache is used and updated.
    """
    result = {"valid": False, "reason": "", "plaintext": None,
              "fingerprint_ok": False, "replay": False, "stage": ""}

    def fail(stage: str, reason: str) -> dict:
        result["stage"], result["reason"] = stage, reason
        return result

    missing = [k for k in (*SIGNED_FIELDS, "signature") if k not in payload]
    if missing:
        return fail("format", f"Malformed message, missing fields: {', '.join(missing)}")

    sender, recipient = payload["from"], payload["to"]
    trust = store.load_trust_store() if trust is None else trust
    entry = trust.get(sender)
    if entry is None:
        return fail("sender", f"Unknown sender '{sender}': no public key on file.")
    try:
        public_key = crypto.public_key_from_pem(entry["public_key_pem"])
    except Exception:  # noqa: BLE001
        return fail("sender", "Stored public key for this sender is unreadable.")

    if pin_fingerprints:
        pins = store.load_pins() if pins is None else pins
        result["fingerprint_ok"] = pins.get(sender) == crypto.fingerprint(public_key)
        if not result["fingerprint_ok"]:
            return fail("pin", "Public-key substitution detected: the key on file does not match "
                               "the pinned fingerprint for this identity.")
    else:
        result["fingerprint_ok"] = True

    try:
        signature = base64.b64decode(payload["signature"], validate=True)
    except Exception:  # noqa: BLE001
        return fail("signature", "INVALID signature: not valid base64.")
    if not crypto.verify(public_key, signature, canonical_bytes(payload)):
        return fail("signature", "INVALID signature: message was altered or signed with a different key.")

    if reader is not None and reader != recipient:
        return fail("recipient", f"Message is addressed to {recipient}, not {reader}.")

    seen_set = None
    if check_replay:
        try:
            sent_at = datetime.fromisoformat(payload["timestamp"])
        except (TypeError, ValueError):
            return fail("timestamp", "REJECTED: unreadable timestamp.")
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - sent_at).total_seconds()
        seen_set = store.load_seen_ids(recipient) if seen is None else seen
        if payload["id"] in seen_set:
            result["replay"] = True
            return fail("replay", "REPLAY detected: this message id was already accepted.")
        if age > max_age:
            return fail("timestamp", f"REJECTED: message is {age/3600:.1f} h old (limit {max_age/3600:.1f} h).")
        if age < -MAX_FUTURE_SKEW_SECONDS:
            return fail("timestamp", "REJECTED: message timestamp is in the future.")

    if decrypt:
        try:
            result["plaintext"] = decrypt_body(payload, reader or recipient)
        except Exception as exc:  # noqa: BLE001
            return fail("decrypt", f"Signature was valid but decryption failed ({type(exc).__name__}).")

    if seen_set is not None:
        seen_set.add(payload["id"])
        if seen is None:
            store.save_seen_ids(recipient, seen_set)

    result["valid"] = True
    result["stage"] = "ok"
    result["reason"] = "VALID signature. Integrity and sender authentication succeeded."
    return result


def deliver(payload: dict) -> dict:
    """Receiver-side delivery: verify, then file into the inbox or the quarantine."""
    recipient = store.canonical_name(str(payload.get("to", "")))
    if recipient is None:
        return {"valid": False, "stage": "recipient", "reason": "Unknown recipient.", "stored": None}
    result = verify_message(payload, reader=recipient, decrypt=False)
    if result["valid"]:
        store.append_inbox(recipient, payload)
        result["stored"] = "inbox"
    else:
        store.append_quarantine(recipient, payload, result["reason"])
        result["stored"] = "quarantine"
    return result