"""Automated edge-case and security unit tests.

Validates boundary conditions, input validation, signature verification,
context and identity binding, tamper resistance, and protocol simulations
for the Diffie-Hellman MITM project.
"""

import os
import unittest
from cryptography.exceptions import InvalidTag

from key_exchange import generate_key_pair
from encryption import decrypt_message, encrypt_message
from authentication import (
    DEFAULT_PROTOCOL_ID,
    generate_signing_key_pair,
    sign_public_key,
    verify_public_key_signature,
)
from protocol import (
    simulate_unauthenticated_mitm,
    simulate_authenticated_exchange,
    simulate_authenticated_mitm_attempt,
)


class TestEdgeCases(unittest.TestCase):
    """Test suite covering edge cases and security guarantees."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.valid_key = os.urandom(32)
        self.sample_plaintext = b"Automated security and edge-case test payload."

    def test_aes_gcm_rejects_modified_authentication_tag(self) -> None:
        """Verify that AES-GCM decryption rejects ciphertext with a tampered tag."""
        nonce, ciphertext = encrypt_message(self.valid_key, self.sample_plaintext)

        # The authentication tag is the last 16 bytes of the ciphertext.
        # Tamper with the final byte of the authentication tag.
        tampered_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])

        with self.assertRaises(InvalidTag):
            decrypt_message(self.valid_key, nonce, tampered_ciphertext)

    def test_aes_gcm_rejects_invalid_nonce_length(self) -> None:
        """Verify that AES-GCM rejects nonces of invalid lengths."""
        nonce, ciphertext = encrypt_message(self.valid_key, self.sample_plaintext)

        # Nonces below 8 bytes are rejected by the underlying AESGCM cipher with ValueError.
        short_nonce = b"short"  # 5 bytes (< 8 bytes)
        with self.assertRaises(ValueError):
            decrypt_message(self.valid_key, short_nonce, ciphertext)

        # Nonces of length >= 8 but != 12 bytes fail AEAD authentication with InvalidTag.
        wrong_len_nonce = os.urandom(16)  # 16 bytes instead of 12
        with self.assertRaises(InvalidTag):
            decrypt_message(self.valid_key, wrong_len_nonce, ciphertext)

    def test_encryption_rejects_non_32_byte_keys(self) -> None:
        """Verify that encrypt_message and decrypt_message reject keys not equal to 32 bytes."""
        nonce = os.urandom(12)
        ciphertext = b"dummy_ciphertext_placeholder"

        invalid_keys = [
            b"",  # 0 bytes
            os.urandom(16),  # 16 bytes (AES-128)
            os.urandom(24),  # 24 bytes (AES-192)
            os.urandom(31),  # 31 bytes
            os.urandom(33),  # 33 bytes
            os.urandom(64),  # 64 bytes
        ]

        for invalid_key in invalid_keys:
            with self.subTest(key_length=len(invalid_key)):
                with self.assertRaises(ValueError):
                    encrypt_message(invalid_key, self.sample_plaintext)

                with self.assertRaises(ValueError):
                    decrypt_message(invalid_key, nonce, ciphertext)

    def test_ed25519_verification_rejects_untrusted_signing_key(self) -> None:
        """Verify that Ed25519 signature verification fails when signed by an untrusted key."""
        _, alice_exchange_public = generate_key_pair()
        _, alice_trusted_signing_public = generate_signing_key_pair()

        # Mallory generates an untrusted identity key and signs Alice's exchange key
        mallory_untrusted_private, _ = generate_signing_key_pair()
        untrusted_signature = sign_public_key(
            mallory_untrusted_private,
            alice_exchange_public,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )

        # Verifying against Alice's trusted signing key must fail
        is_valid = verify_public_key_signature(
            alice_trusted_signing_public,
            alice_exchange_public,
            untrusted_signature,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )
        self.assertFalse(is_valid)

    def test_ed25519_verification_rejects_substituted_exchange_public_key(self) -> None:
        """Verify that Ed25519 verification fails if the X25519 public key is substituted."""
        alice_signing_private, alice_signing_public = generate_signing_key_pair()
        _, alice_exchange_public = generate_key_pair()
        alice_signature = sign_public_key(
            alice_signing_private,
            alice_exchange_public,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )

        # Mallory generates a substituted exchange key
        _, mallory_exchange_public = generate_key_pair()

        # Bob verifies Mallory's key using Alice's signature and Alice's trusted public key
        is_valid = verify_public_key_signature(
            alice_signing_public,
            mallory_exchange_public,
            alice_signature,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )
        self.assertFalse(is_valid)

    def test_ed25519_verification_rejects_wrong_sender(self) -> None:
        """Verify that Ed25519 verification fails if the sender identity differs."""
        alice_signing_private, alice_signing_public = generate_signing_key_pair()
        _, alice_exchange_public = generate_key_pair()

        # Alice signs with sender_id=b"Alice", recipient_id=b"Bob"
        alice_signature = sign_public_key(
            alice_signing_private,
            alice_exchange_public,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )

        # Verifier expects sender_id=b"Charlie" (wrong sender)
        is_valid = verify_public_key_signature(
            alice_signing_public,
            alice_exchange_public,
            alice_signature,
            sender_id=b"Charlie",
            recipient_id=b"Bob",
        )
        self.assertFalse(is_valid)

    def test_ed25519_verification_rejects_wrong_recipient(self) -> None:
        """Verify that Ed25519 verification fails if the intended recipient identity differs."""
        alice_signing_private, alice_signing_public = generate_signing_key_pair()
        _, alice_exchange_public = generate_key_pair()

        # Alice signs intended for recipient Bob
        alice_signature = sign_public_key(
            alice_signing_private,
            alice_exchange_public,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )

        # Verifier checks for recipient David (misbinding / unknown key-share attempt)
        is_valid = verify_public_key_signature(
            alice_signing_public,
            alice_exchange_public,
            alice_signature,
            sender_id=b"Alice",
            recipient_id=b"David",
        )
        self.assertFalse(is_valid)

    def test_ed25519_verification_rejects_wrong_protocol_context(self) -> None:
        """Verify that Ed25519 verification fails if the protocol identifier differs."""
        alice_signing_private, alice_signing_public = generate_signing_key_pair()
        _, alice_exchange_public = generate_key_pair()

        # Signed under default protocol ID (b"dh-mitm-v2")
        alice_signature = sign_public_key(
            alice_signing_private,
            alice_exchange_public,
            sender_id=b"Alice",
            recipient_id=b"Bob",
            protocol_id=DEFAULT_PROTOCOL_ID,
        )

        # Verifier specifies a different/older protocol version (cross-protocol attempt)
        is_valid = verify_public_key_signature(
            alice_signing_public,
            alice_exchange_public,
            alice_signature,
            sender_id=b"Alice",
            recipient_id=b"Bob",
            protocol_id=b"dh-mitm-v1-legacy",
        )
        self.assertFalse(is_valid)

    def test_unauthenticated_mitm_simulation_succeeds(self) -> None:
        """Verify that the unauthenticated MITM simulation demonstrates a successful attack."""
        result = simulate_unauthenticated_mitm()

        self.assertTrue(result["attack_succeeded"])
        self.assertTrue(result["alice_mallory_secret_match"])
        self.assertTrue(result["bob_mallory_secret_match"])
        self.assertFalse(result["alice_bob_secret_match"])
        self.assertTrue(result["eavesdropping_successful"])
        self.assertTrue(result["relay_successful"])

    def test_authenticated_exchange_simulation_succeeds(self) -> None:
        """Verify that the authenticated key exchange simulation completes successfully."""
        result = simulate_authenticated_exchange()

        self.assertTrue(result["authentication_successful"])
        self.assertTrue(result["shared_secrets_match"])
        self.assertTrue(result["message_decryption_successful"])
        self.assertTrue(result["exchange_successful"])

    def test_authenticated_mitm_attempt_is_blocked(self) -> None:
        """Verify that the authenticated MITM attempt is detected and blocked."""
        result = simulate_authenticated_mitm_attempt()

        self.assertFalse(result["authentication_successful"])
        self.assertTrue(result["mitm_attack_blocked"])
        self.assertFalse(result["shared_secrets_match"])
        self.assertFalse(result["message_decryption_successful"])
        self.assertFalse(result["exchange_successful"])


if __name__ == "__main__":
    unittest.main()
