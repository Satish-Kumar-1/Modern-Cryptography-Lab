#!/usr/bin/env python3
"""
Project 2: Secure Messaging With Digital Signatures
Member 1: Core Cryptography & Key Management (crypto_core.py)

Primitives:
  - Digital Signatures: Ed25519 (RFC 8032)
  - Optional Confidentiality: AES-256-GCM (Encrypt-then-Sign)
  - Key Directory: Out-of-Band SHA-256 Key Fingerprinting
  - Anti-Replay: Monotonic Sequence Counters, UUIDv4 msg_id, and Timestamps
"""

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecurityError(Exception):
    """Raised when public-key substitution or security policy violations occur."""
    pass


class PublicKeyDirectory:
    """
    Central Public-Key Directory with Out-of-Band Fingerprint Verification.
    Simulates both unauthenticated lookups and trusted fingerprint pin validation.
    """

    def __init__(self) -> None:
        self.registry: dict[str, ed25519.Ed25519PublicKey] = {}
        self.trusted_fingerprints: dict[str, str] = {}

    @staticmethod
    def compute_fingerprint(pub_key: ed25519.Ed25519PublicKey) -> str:
        """Computes the SHA-256 hex digest of the raw 32-byte Ed25519 public key."""
        raw_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw_bytes).hexdigest()

    def register_user(
        self,
        username: str,
        pub_key: ed25519.Ed25519PublicKey,
        update_trusted_fingerprint: bool = True
    ) -> str:
        """
        Registers a user's public key in the directory.
        Optionally saves the SHA-256 fingerprint in the out-of-band trusted registry.
        """
        self.registry[username] = pub_key
        fingerprint = self.compute_fingerprint(pub_key)
        if update_trusted_fingerprint:
            self.trusted_fingerprints[username] = fingerprint
        return fingerprint

    def tamper_registry_key(self, username: str, fake_pub_key: ed25519.Ed25519PublicKey) -> None:
        """
        Simulates an in-directory public-key substitution attack by replacing the registered
        public key WITHOUT updating the out-of-band trusted fingerprint.
        """
        self.registry[username] = fake_pub_key

    def get_public_key(self, username: str, verify_fingerprint: bool = True) -> ed25519.Ed25519PublicKey:
        """
        Fetches the public key for a user from the directory.
        If verify_fingerprint=True, checks against the trusted out-of-band fingerprint.
        """
        if username not in self.registry:
            raise KeyError(f"User '{username}' is not registered in the public key directory.")

        pub_key = self.registry[username]

        if verify_fingerprint:
            current_fp = self.compute_fingerprint(pub_key)
            trusted_fp = self.trusted_fingerprints.get(username)
            if trusted_fp is None or current_fp != trusted_fp:
                raise SecurityError(
                    f"PUBLIC KEY SUBSTITUTION DETECTED: Directory key fingerprint for '{username}' "
                    f"({current_fp[:16]}...) does not match trusted out-of-band fingerprint ({trusted_fp[:16] if trusted_fp else 'None'}...)!"
                )

        return pub_key

    def get_public_key_hex(self, username: str) -> str:
        """Returns the 64-character hex string of the user's currently registered public key."""
        if username not in self.registry:
            raise KeyError(f"User '{username}' not registered.")
        raw_bytes = self.registry[username].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw_bytes.hex()


class User:
    """
    Represents a secure messaging participant (Alice, Bob, or Mallory).
    Manages private/public keys, message signing, encryption, and verification.
    """

    def __init__(self, name: str, directory: PublicKeyDirectory) -> None:
        self.name: str = name
        self.directory: PublicKeyDirectory = directory

        # Generate fresh Ed25519 key pair
        self.private_key: ed25519.Ed25519PrivateKey = ed25519.Ed25519PrivateKey.generate()
        self.public_key: ed25519.Ed25519PublicKey = self.private_key.public_key()

        # Register public key and trusted fingerprint in the central directory
        self.directory.register_user(self.name, self.public_key, update_trusted_fingerprint=True)

        # Stateful replay defense tracking
        self.msg_counter: int = 0
        self.seen_messages: set[tuple[str, int]] = set()
        self.last_counter_per_sender: dict[str, int] = {}

    def get_public_key_hex(self) -> str:
        """Returns 64-character hex string of self.public_key."""
        raw_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw_bytes.hex()

    def get_fingerprint(self) -> str:
        """Returns SHA-256 fingerprint of self.public_key."""
        return PublicKeyDirectory.compute_fingerprint(self.public_key)

    def save_public_key_pem(self, filepath: str) -> None:
        """
        Saves only the public key in PEM format to filepath.
        Note: Private keys are NEVER exported or tracked in Git.
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        path.write_bytes(pem_bytes)

    def sign_message(
        self,
        recipient: str,
        plaintext: str,
        shared_aes_key: bytes | None = None,
        custom_counter: int | None = None,
        custom_timestamp: int | None = None
    ) -> dict:
        """
        Builds the message envelope and computes the Ed25519 signature over canonical JSON.
        Optionally performs AES-256-GCM encryption before signing (Encrypt-then-Sign).
        """
        if custom_counter is not None:
            counter = custom_counter
        else:
            self.msg_counter += 1
            counter = self.msg_counter

        timestamp = custom_timestamp if custom_timestamp is not None else int(time.time())

        # Optional AES-256-GCM Confidentiality
        if shared_aes_key is not None:
            nonce = os.urandom(12)
            aesgcm = AESGCM(shared_aes_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            payload = base64.b64encode(ciphertext).decode('utf-8')
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            encrypted = True
        else:
            payload = plaintext
            nonce_b64 = None
            encrypted = False

        envelope = {
            "sender": self.name,
            "recipient": recipient,
            "payload": payload,
            "encrypted": encrypted,
            "nonce": nonce_b64,
            "counter": counter,
            "timestamp": timestamp,
            "msg_id": str(uuid.uuid4())
        }

        # Deterministic canonical JSON serialization
        canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature_bytes = self.private_key.sign(canonical_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        return {
            "envelope": envelope,
            "signature": signature_b64
        }

    def verify_message(
        self,
        packet: dict,
        enforce_replay_defense: bool = True,
        verify_key_fingerprint: bool = True,
        shared_aes_key: bytes | None = None,
        max_age_seconds: int = 300
    ) -> dict:
        """
        Verifies a received packet through a multi-stage security pipeline.
        Never crashes on malformed inputs or malicious attacks. Always returns a structured dictionary.
        """
        # Step 1: Validate packet structure
        if not isinstance(packet, dict) or "envelope" not in packet or "signature" not in packet:
            return {
                "valid": False,
                "sender": "UNKNOWN",
                "recipient": self.name,
                "status_code": "MALFORMED_PACKET",
                "reason": "Packet is missing required 'envelope' or 'signature' top-level keys.",
                "plaintext": None,
                "encrypted": False,
                "counter": None,
                "timestamp": None,
                "signature_hex_preview": "N/A"
            }

        envelope = packet.get("envelope")
        if not isinstance(envelope, dict):
            return {
                "valid": False,
                "sender": "UNKNOWN",
                "recipient": self.name,
                "status_code": "MALFORMED_PACKET",
                "reason": "Envelope must be a JSON dictionary.",
                "plaintext": None,
                "encrypted": False,
                "counter": None,
                "timestamp": None,
                "signature_hex_preview": "N/A"
            }

        sender = envelope.get("sender", "UNKNOWN")
        recipient = envelope.get("recipient", "UNKNOWN")
        counter = envelope.get("counter")
        timestamp = envelope.get("timestamp")
        encrypted = bool(envelope.get("encrypted", False))

        # Preview signature bytes
        signature_b64 = packet.get("signature", "")
        try:
            sig_raw = base64.b64decode(signature_b64)
            sig_hex_preview = sig_raw.hex()[:32]
        except Exception:
            sig_raw = b""
            sig_hex_preview = "MALFORMED_B64"

        # Step 2: Retrieve sender's public key & verify out-of-band fingerprint
        try:
            sender_pub_key = self.directory.get_public_key(sender, verify_fingerprint=verify_key_fingerprint)
        except SecurityError as sec_err:
            return {
                "valid": False,
                "sender": sender,
                "recipient": recipient,
                "status_code": "KEY_SUBSTITUTION_DETECTED",
                "reason": str(sec_err),
                "plaintext": None,
                "encrypted": encrypted,
                "counter": counter,
                "timestamp": timestamp,
                "signature_hex_preview": sig_hex_preview
            }
        except KeyError as key_err:
            return {
                "valid": False,
                "sender": sender,
                "recipient": recipient,
                "status_code": "UNKNOWN_SENDER",
                "reason": str(key_err),
                "plaintext": None,
                "encrypted": encrypted,
                "counter": counter,
                "timestamp": timestamp,
                "signature_hex_preview": sig_hex_preview
            }

        # Step 3: Verify Ed25519 digital signature
        try:
            canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8')
            if len(sig_raw) != 64:
                raise InvalidSignature("Signature length is not 64 bytes.")
            sender_pub_key.verify(sig_raw, canonical_bytes)
        except (InvalidSignature, Exception) as sig_err:
            return {
                "valid": False,
                "sender": sender,
                "recipient": recipient,
                "status_code": "INVALID_SIGNATURE",
                "reason": f"Ed25519 cryptographic signature verification failed: {sig_err}",
                "plaintext": None,
                "encrypted": encrypted,
                "counter": counter,
                "timestamp": timestamp,
                "signature_hex_preview": sig_hex_preview
            }

        # Step 4: Stateful Replay Defense
        if enforce_replay_defense:
            if counter is None or timestamp is None:
                return {
                    "valid": False,
                    "sender": sender,
                    "recipient": recipient,
                    "status_code": "REPLAY_DETECTED",
                    "reason": "Missing monotonic sequence counter or timestamp in envelope.",
                    "plaintext": None,
                    "encrypted": encrypted,
                    "counter": counter,
                    "timestamp": timestamp,
                    "signature_hex_preview": sig_hex_preview
                }

            # Check if (sender, counter) has already been processed or is not strictly monotonic
            last_counter = self.last_counter_per_sender.get(sender, 0)
            if (sender, counter) in self.seen_messages or counter <= last_counter:
                return {
                    "valid": False,
                    "sender": sender,
                    "recipient": recipient,
                    "status_code": "REPLAY_DETECTED",
                    "reason": (
                        f"Replayed message detected! Counter {counter} has already been accepted "
                        f"or is not strictly greater than last processed counter ({last_counter}) for sender '{sender}'."
                    ),
                    "plaintext": None,
                    "encrypted": encrypted,
                    "counter": counter,
                    "timestamp": timestamp,
                    "signature_hex_preview": sig_hex_preview
                }

            # Check timestamp expiration window
            current_time = int(time.time())
            if abs(current_time - timestamp) > max_age_seconds:
                return {
                    "valid": False,
                    "sender": sender,
                    "recipient": recipient,
                    "status_code": "EXPIRED_TIMESTAMP",
                    "reason": (
                        f"Message timestamp ({timestamp}) is outside the acceptable {max_age_seconds}s "
                        f"window (current time: {current_time}, delta: {abs(current_time - timestamp)}s)."
                    ),
                    "plaintext": None,
                    "encrypted": encrypted,
                    "counter": counter,
                    "timestamp": timestamp,
                    "signature_hex_preview": sig_hex_preview
                }

            # Record message state
            self.seen_messages.add((sender, counter))
            self.last_counter_per_sender[sender] = counter

        # Step 5: Confidentiality Decryption
        if encrypted:
            if shared_aes_key is None:
                return {
                    "valid": False,
                    "sender": sender,
                    "recipient": recipient,
                    "status_code": "DECRYPTION_FAILED",
                    "reason": "Payload is marked encrypted (AES-256-GCM), but no shared AES key was supplied.",
                    "plaintext": None,
                    "encrypted": True,
                    "counter": counter,
                    "timestamp": timestamp,
                    "signature_hex_preview": sig_hex_preview
                }

            try:
                nonce_b64 = envelope.get("nonce")
                if not nonce_b64:
                    raise ValueError("Missing nonce in encrypted envelope.")
                nonce = base64.b64decode(nonce_b64)
                ciphertext = base64.b64decode(envelope.get("payload", ""))
                aesgcm = AESGCM(shared_aes_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                recovered_plaintext = decrypted_bytes.decode('utf-8')
            except Exception as dec_err:
                return {
                    "valid": False,
                    "sender": sender,
                    "recipient": recipient,
                    "status_code": "DECRYPTION_FAILED",
                    "reason": f"AES-256-GCM decryption failed: {dec_err}",
                    "plaintext": None,
                    "encrypted": True,
                    "counter": counter,
                    "timestamp": timestamp,
                    "signature_hex_preview": sig_hex_preview
                }
        else:
            recovered_plaintext = envelope.get("payload")

        # Step 6: All security checks passed
        return {
            "valid": True,
            "sender": sender,
            "recipient": recipient,
            "status_code": "SUCCESS",
            "reason": "Signature verified under sender public key. All replay & integrity checks passed.",
            "plaintext": recovered_plaintext,
            "encrypted": encrypted,
            "counter": counter,
            "timestamp": timestamp,
            "signature_hex_preview": sig_hex_preview
        }


# Self-Test Execution Block
if __name__ == "__main__":
    print("[*] Running crypto_core.py self-test block...")

    directory = PublicKeyDirectory()
    alice = User("Alice", directory)
    bob = User("Bob", directory)

    print(f"[+] Alice Public Key Hex: {alice.get_public_key_hex()[:32]}...")
    print(f"[+] Alice Fingerprint:    {alice.get_fingerprint()[:32]}...")
    print(f"[+] Bob Public Key Hex:   {bob.get_public_key_hex()[:32]}...")
    print(f"[+] Bob Fingerprint:      {bob.get_fingerprint()[:32]}...")

    # Test 1: Normal unencrypted signed message
    packet1 = alice.sign_message(
        recipient="Bob",
        plaintext="Hello Bob! This is an authentic Ed25519-signed message."
    )
    result1 = bob.verify_message(packet1)
    print(f"[+] Test 1 (Unencrypted): valid={result1['valid']}, status_code={result1['status_code']}")
    assert result1["valid"] is True, f"Test 1 failed: {result1}"
    assert result1["plaintext"] == "Hello Bob! This is an authentic Ed25519-signed message."

    # Test 2: AES-256-GCM encrypted signed message
    shared_key = AESGCM.generate_key(bit_length=256)
    packet2 = alice.sign_message(
        recipient="Bob",
        plaintext="Top Secret Message: Encrypt-then-Sign AES-256-GCM",
        shared_aes_key=shared_key
    )
    result2 = bob.verify_message(packet2, shared_aes_key=shared_key)
    print(f"[+] Test 2 (Encrypted):   valid={result2['valid']}, status_code={result2['status_code']}")
    assert result2["valid"] is True, f"Test 2 failed: {result2}"
    assert result2["plaintext"] == "Top Secret Message: Encrypt-then-Sign AES-256-GCM"

    print("[SUCCESS] All crypto_core.py self-tests PASSED successfully!")
