# AI Agent Specification: Member 1 — Core Cryptography & Key Management (`crypto_core.py`)

## 1. Project Context & Role
You are an expert Cryptography & Security Software Engineer building the core backend module (`crypto_core.py`) for **Project 2: Secure Messaging With Digital Signatures**. 
This is a 3-person team project written in **Python 3.10+** using the official `cryptography` library (`pip install cryptography`).
Your module (`crypto_core.py`) will be imported by Member 2 (`experiments.py`) and Member 3 (`app.py`). **You must strictly adhere to the class names, method signatures, and data structures defined below so the team's code integrates seamlessly.**

---

## 2. Technical Requirements & Cryptographic Primitives
1. **Language & Library:** Python 3.10+ using `cryptography.hazmat.primitives`. Do NOT implement cryptographic algorithms from scratch.
2. **Digital Signature Scheme:** **Ed25519** (`cryptography.hazmat.primitives.asymmetric.ed25519`).
3. **Confidentiality Extension (Optional/Bonus Requirement included):** **AES-256-GCM** (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`) with a 12-byte (96-bit) cryptographically secure random nonce (`os.urandom(12)`).
4. **Public-Key Authentication:** SHA-256 key fingerprinting (`hashlib.sha256`) to simulate an out-of-band trusted fingerprint verification mechanism and detect Public-Key Substitution attacks.
5. **Replay Attack Protection:** Monotonically increasing message counters (`counter`), unique message IDs (`msg_id`), and UTC timestamps (`timestamp`), tracked per-sender by the receiver.

---

## 3. Exact Data Structures & Packet Format
Every signed message transmitted between users (`Alice` and `Bob`) MUST be a Python `dict` following this exact structure:

```json
{
  "envelope": {
    "sender": "Alice",
    "recipient": "Bob",
    "payload": "Hello Bob! (or Base64 ciphertext if encrypted=True)",
    "encrypted": false,
    "nonce": null,
    "counter": 1,
    "timestamp": 1730000000,
    "msg_id": "uuid4-string"
  },
  "signature": "base64-encoded-64-byte-ed25519-signature"
}
```

### Canonical Serialization Rule for Signing:
When signing or verifying the `"envelope"`, always serialize it deterministically using:
```python
canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8')
```
Also, if AES-GCM encryption is enabled (`encrypted=True`), pass `canonical_aad` (sender + recipient + counter + timestamp + msg_id) or `None` consistently. To keep tamper testing clear, pass `None` as `associated_data` in `aesgcm.encrypt(nonce, plaintext_bytes, None)` because the entire `envelope` (including `nonce`, `payload`, `sender`, `counter`) is covered by the Ed25519 signature (**Encrypt-then-Sign** pattern).

---

## 4. Required Classes & Method Signatures in `crypto_core.py`

### 4.1 Custom Exception
```python
class SecurityError(Exception):
    """Raised when public-key substitution or security policy violations occur."""
    pass
```

### 4.2 Class: `PublicKeyDirectory`
Simulates a central public-key directory that maps usernames to their `Ed25519PublicKey` and stores an out-of-band "trusted fingerprint" registry to demonstrate Public-Key Substitution attacks and defenses.

* `__init__(self)`:
  * `self.registry: dict[str, ed25519.Ed25519PublicKey] = {}`
  * `self.trusted_fingerprints: dict[str, str] = {}` (stores hex SHA-256 digest of raw 32-byte public key)
* ` compute_fingerprint(pub_key: ed25519.Ed25519PublicKey) -> str` (Static or helper method):
  * Extracts raw 32 bytes via `pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)` and returns `hashlib.sha256(raw_bytes).hexdigest()`.
* `register_user(self, username: str, pub_key: ed25519.Ed25519PublicKey, update_trusted_fingerprint: bool = True) -> str`:
  * Stores `pub_key` in `self.registry[username]`.
  * If `update_trusted_fingerprint` is `True`, computes and saves the SHA-256 fingerprint in `self.trusted_fingerprints[username]`.
  * Returns the hex fingerprint.
* `tamper_registry_key(self, username: str, fake_pub_key: ed25519.Ed25519PublicKey) -> None`:
  * Overwrites `self.registry[username] = fake_pub_key` **without** updating `self.trusted_fingerprints[username]`. Used to simulate a Public-Key Substitution attack in the directory.
* `get_public_key(self, username: str, verify_fingerprint: bool = True) -> ed25519.Ed25519PublicKey`:
  * Fetches `pub_key` from `self.registry`. Raises `KeyError` if missing.
  * If `verify_fingerprint=True`, recalculates the SHA-256 fingerprint of the fetched key and compares it against `self.trusted_fingerprints[username]`. If they do not match, raises `SecurityError("PUBLIC KEY SUBSTITUTION DETECTED: Directory key fingerprint does not match trusted out-of-band fingerprint!")`.
  * Returns `pub_key`.
* `get_public_key_hex(self, username: str) -> str`:
  * Returns the hex string of the user's currently registered public key for display/logging.

### 4.3 Class: `User`
Represents a messaging participant (`Alice`, `Bob`, or `Mallory`).

* `__init__(self, name: str, directory: PublicKeyDirectory)`:
  * Sets `self.name = name` and `self.directory = directory`.
  * Generates an Ed25519 key pair (`self.private_key = ed25519.Ed25519PrivateKey.generate()`, `self.public_key = self.private_key.public_key()`).
  * Registers the user in `self.directory.register_user(self.name, self.public_key, update_trusted_fingerprint=True)`.
  * Initializes `self.msg_counter: int = 0`.
  * Initializes `self.seen_messages: set[tuple[str, int]] = set()` (stores `(sender, counter)` pairs) and `self.last_counter_per_sender: dict[str, int] = {}`.
* `get_public_key_hex(self) -> str`:
  * Returns 64-character hex string of `self.public_key`.
* `get_fingerprint(self) -> str`:
  * Returns SHA-256 fingerprint of `self.public_key`.
* `save_public_key_pem(self, filepath: str) -> None`:
  * Saves only the public key in PEM format. (Never save unencrypted private keys to tracked repository files).
* `sign_message(self, recipient: str, plaintext: str, shared_aes_key: bytes | None = None, custom_counter: int | None = None, custom_timestamp: int | None = None) -> dict`:
  * Increments `self.msg_counter` (unless `custom_counter` is provided).
  * If `shared_aes_key` is provided (32 bytes):
    * Generates 12-byte nonce via `os.urandom(12)`.
    * Encrypts `plaintext.encode('utf-8')` using `AESGCM(shared_aes_key).encrypt(nonce, plaintext.encode('utf-8'), None)`.
    * Sets `payload = base64.b64encode(ciphertext).decode('utf-8')`, `nonce_b64 = base64.b64encode(nonce).decode('utf-8')`, and `encrypted = True`.
  * Else:
    * Sets `payload = plaintext`, `nonce_b64 = None`, and `encrypted = False`.
  * Builds the `"envelope"` dict with `sender`, `recipient`, `payload`, `encrypted`, `nonce`, `counter`, `timestamp`, and `msg_id` (`str(uuid.uuid4())`).
  * Signs the canonical JSON bytes of `"envelope"` using `self.private_key.sign(canonical_bytes)`.
  * Returns `{"envelope": envelope, "signature": base64.b64encode(signature).decode('utf-8')}`.
* `verify_message(self, packet: dict, enforce_replay_defense: bool = True, verify_key_fingerprint: bool = True, shared_aes_key: bytes | None = None, max_age_seconds: int = 300) -> dict`:
  * Must NEVER crash on malformed inputs or bad signatures. Always return a structured status dictionary:
    ```python
    {
      "valid": bool,               # True only if ALL enabled security checks pass
      "sender": str,               # Claimed sender from envelope
      "recipient": str,            # Claimed recipient
      "status_code": str,          # e.g., "SUCCESS", "INVALID_SIGNATURE", "KEY_SUBSTITUTION_DETECTED", "REPLAY_DETECTED", "DECRYPTION_FAILED", "MALFORMED_PACKET"
      "reason": str,               # Clear human-readable explanation for logs/UI
      "plaintext": str | None,     # Recovered message if valid (or raw payload if unencrypted)
      "encrypted": bool,           # Whether payload was AES-GCM encrypted
      "counter": int | None,
      "timestamp": int | None,
      "signature_hex_preview": str # First 32 hex chars of signature for logging
    }
    ```
  * **Verification Order of Operations:**
    1. Validate packet structure (`envelope` and `signature` keys present).
    2. Retrieve sender's public key via `self.directory.get_public_key(sender, verify_fingerprint=verify_key_fingerprint)`. Catch `SecurityError` and return `valid=False, status_code="KEY_SUBSTITUTION_DETECTED"`.
    3. Verify Ed25519 signature over canonical JSON bytes of `envelope`. Catch `InvalidSignature` and return `valid=False, status_code="INVALID_SIGNATURE"`.
    4. If `enforce_replay_defense=True`:
       * Check if `counter` is `None` or `timestamp` is `None` -> reject.
       * Check if `(sender, counter)` is in `self.seen_messages` or `counter <= self.last_counter_per_sender.get(sender, 0)` -> return `valid=False, status_code="REPLAY_DETECTED"`.
       * Check if `abs(int(time.time()) - timestamp) > max_age_seconds` -> return `valid=False, status_code="EXPIRED_TIMESTAMP"`.
       * Record `(sender, counter)` in `self.seen_messages` and update `self.last_counter_per_sender[sender] = counter`.
    5. If `envelope["encrypted"]` is `True`:
       * Require `shared_aes_key` and decrypt using `AESGCM(shared_aes_key).decrypt(nonce, ciphertext, None)`. Catch exceptions and return `valid=False, status_code="DECRYPTION_FAILED"`.
    6. Return `valid=True, status_code="SUCCESS"`, including the verified plaintext.

---

## 5. Self-Test Block (`if __name__ == "__main__":`)
Include a self-test block at the bottom of `crypto_core.py` that instantiates `PublicKeyDirectory`, `Alice`, and `Bob`, tests one normal unencrypted signed message, tests one AES-GCM encrypted signed message, and asserts that both return `result["valid"] is True`. Also generate `.gitignore` rules inside a comment block reminding the team to ignore `*.pem` and `__pycache__/`.