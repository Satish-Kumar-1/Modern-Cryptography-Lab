"""Unit tests for Ed25519 Key Generation and Management (Person 1).

Covers:
- Key pair generation
- Key serialization (PKCS#8 PEM, SPKI PEM, raw bytes)
- Encrypted private key storage and passphrase validation
- Error handling on malformed keys and incorrect passwords
"""

import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.key_manager import (
    InvalidPassphraseError,
    KeyFormatError,
    KeyManager,
    PassphraseError,
)


class TestKeyGeneration(unittest.TestCase):
    """Tests for KeyManager functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_key_pair(self):
        """Verify that generate_key_pair returns valid Ed25519 key instances."""
        priv_key, pub_key = KeyManager.generate_key_pair()
        self.assertIsInstance(priv_key, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(pub_key, ed25519.Ed25519PublicKey)

    def test_save_and_load_unencrypted_private_key(self):
        """Test saving and reloading an unencrypted private key."""
        priv_key, _ = KeyManager.generate_key_pair()
        priv_path = self.temp_path / "test_private.pem"

        saved_path = KeyManager.save_private_key(priv_key, priv_path)
        self.assertTrue(saved_path.is_file())

        loaded_key = KeyManager.load_private_key(priv_path)
        self.assertIsInstance(loaded_key, ed25519.Ed25519PrivateKey)

        # Confirm they produce identical signatures
        test_payload = b"test consistency"
        sig1 = priv_key.sign(test_payload)
        sig2 = loaded_key.sign(test_payload)
        self.assertEqual(sig1, sig2)

    def test_save_and_load_encrypted_private_key(self):
        """Test saving with passphrase encryption and loading with correct/incorrect passphrase."""
        priv_key, _ = KeyManager.generate_key_pair()
        priv_path = self.temp_path / "enc_private.pem"
        password = "SuperSecretPassphrase123!"

        KeyManager.save_private_key(priv_key, priv_path, password=password)

        # Verify key file contains encrypted PEM header or markers
        with open(priv_path, "rb") as f:
            content = f.read()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", content)

        # 1. Loading with correct password should succeed
        loaded_key = KeyManager.load_private_key(priv_path, password=password)
        self.assertIsInstance(loaded_key, ed25519.Ed25519PrivateKey)

        # 2. Loading with incorrect password should raise InvalidPassphraseError
        with self.assertRaises(InvalidPassphraseError):
            KeyManager.load_private_key(priv_path, password="WrongPassword!")

        # 3. Loading without password should raise PassphraseError
        with self.assertRaises(PassphraseError):
            KeyManager.load_private_key(priv_path, password=None)

    def test_save_and_load_public_key(self):
        """Test saving and reloading public key in SubjectPublicKeyInfo PEM format."""
        _, pub_key = KeyManager.generate_key_pair()
        pub_path = self.temp_path / "test_public.pem"

        saved_path = KeyManager.save_public_key(pub_key, pub_path)
        self.assertTrue(saved_path.is_file())

        with open(pub_path, "r", encoding="ascii") as f:
            pem_text = f.read()
        self.assertIn("-----BEGIN PUBLIC KEY-----", pem_text)
        self.assertIn("-----END PUBLIC KEY-----", pem_text)

        loaded_pub = KeyManager.load_public_key(pub_path)
        self.assertIsInstance(loaded_pub, ed25519.Ed25519PublicKey)

        # Both keys should have identical raw bytes
        raw_original = KeyManager.export_public_key_raw(pub_key)
        raw_loaded = KeyManager.export_public_key_raw(loaded_pub)
        self.assertEqual(raw_original, raw_loaded)

    def test_load_public_key_from_raw_bytes(self):
        """Test loading public key directly from 32 raw bytes."""
        _, pub_key = KeyManager.generate_key_pair()
        raw_bytes = KeyManager.export_public_key_raw(pub_key)
        self.assertEqual(len(raw_bytes), 32)

        reloaded = KeyManager.load_public_key(raw_bytes)
        self.assertEqual(KeyManager.export_public_key_raw(reloaded), raw_bytes)

    def test_malformed_key_handling(self):
        """Test that malformed key files raise KeyFormatError without crashing."""
        bad_path = self.temp_path / "corrupted.pem"
        with open(bad_path, "wb") as f:
            f.write(b"NOT_A_VALID_PEM_OR_KEY_DATA")

        with self.assertRaises(KeyFormatError):
            KeyManager.load_public_key(bad_path)

        with self.assertRaises(KeyFormatError):
            KeyManager.load_private_key(bad_path)

    def test_missing_file_handling(self):
        """Test that non-existent paths raise FileNotFoundError."""
        missing = self.temp_path / "non_existent.pem"
        with self.assertRaises(FileNotFoundError):
            KeyManager.load_public_key(missing)

        with self.assertRaises(FileNotFoundError):
            KeyManager.load_private_key(missing)


if __name__ == "__main__":
    unittest.main()
