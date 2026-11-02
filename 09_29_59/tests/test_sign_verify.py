"""Integration and Unit Tests for Document Signing and Verification (Person 1 + Person 2).

Covers:
- Raw byte signing and verification
- Document file signing and detached signature creation
- Verifying legitimate documents
- Detection of modified document content (tampering)
- Detection of wrong public key
- Detection of corrupted signature
- Safe handling of malformed inputs without crashing
- Verification of repository sample artifacts
"""

import tempfile
import unittest
from pathlib import Path

from src.document_signer import DocumentSigner
from src.key_fingerprint import KeyFingerprint
from src.key_manager import KeyManager
from src.signature_verifier import SignatureVerifier


class TestSignVerify(unittest.TestCase):
    """Tests for signing and verification workflows."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Generate standard test keys
        self.priv_key, self.pub_key = KeyManager.generate_key_pair()
        self.pub_key_path = self.temp_path / "test_pub.pem"
        KeyManager.save_public_key(self.pub_key, self.pub_key_path)

        # Create a sample document
        self.doc_path = self.temp_path / "document.txt"
        self.doc_content = b"This is the official university degree text to be signed."
        with open(self.doc_path, "wb") as f:
            f.write(self.doc_content)

        # Sign the document
        self.sig_path = self.temp_path / "document.sig"
        self.signature = DocumentSigner.sign_document(
            self.doc_path,
            self.priv_key,
            signature_output_path=self.sig_path
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detached_signature_properties(self):
        """Confirm detached signature is 64 bytes and separate from original document."""
        self.assertTrue(self.sig_path.is_file())
        with open(self.sig_path, "rb") as f:
            sig_bytes = f.read()
        self.assertEqual(len(sig_bytes), 64)
        self.assertEqual(sig_bytes, self.signature)

        # Confirm original document file was not altered
        with open(self.doc_path, "rb") as f:
            current_doc = f.read()
        self.assertEqual(current_doc, self.doc_content)

    def test_successful_verification(self):
        """Confirm that original document verifies successfully with correct key and signature."""
        result = SignatureVerifier.verify_document(
            document_path=self.doc_path,
            signature_source=self.sig_path,
            public_key_source=self.pub_key_path
        )
        self.assertTrue(result.is_valid)
        self.assertIn("SUCCEEDED", result.message)

    def test_document_tampering_fails(self):
        """Confirm that any modification of document bytes causes verification to fail."""
        tampered_doc_path = self.temp_path / "tampered_doc.txt"
        tampered_content = self.doc_content + b" [tampered]"
        with open(tampered_doc_path, "wb") as f:
            f.write(tampered_content)

        result = SignatureVerifier.verify_document(
            document_path=tampered_doc_path,
            signature_source=self.sig_path,
            public_key_source=self.pub_key_path
        )
        self.assertFalse(result.is_valid)
        self.assertIn("FAILED", result.message)

    def test_wrong_public_key_fails(self):
        """Confirm that verification fails when an unrelated public key is supplied."""
        _, wrong_pub = KeyManager.generate_key_pair()
        wrong_pub_path = self.temp_path / "wrong_pub.pem"
        KeyManager.save_public_key(wrong_pub, wrong_pub_path)

        result = SignatureVerifier.verify_document(
            document_path=self.doc_path,
            signature_source=self.sig_path,
            public_key_source=wrong_pub_path
        )
        self.assertFalse(result.is_valid)
        self.assertIn("FAILED", result.message)

    def test_signature_tampering_fails(self):
        """Confirm that altering any byte in the 64-byte signature causes verification to fail."""
        corrupted_sig_bytes = bytearray(self.signature)
        # Flip bits in the first byte
        corrupted_sig_bytes[0] ^= 0xFF

        corrupted_sig_path = self.temp_path / "corrupted.sig"
        with open(corrupted_sig_path, "wb") as f:
            f.write(corrupted_sig_bytes)

        result = SignatureVerifier.verify_document(
            document_path=self.doc_path,
            signature_source=corrupted_sig_path,
            public_key_source=self.pub_key_path
        )
        self.assertFalse(result.is_valid)

    def test_malformed_inputs_handled_safely(self):
        """Confirm system handles invalid/corrupted files gracefully without crashing."""
        # 1. Truncated signature (< 64 bytes)
        truncated_sig_path = self.temp_path / "truncated.sig"
        with open(truncated_sig_path, "wb") as f:
            f.write(b"too_short")

        res_trunc = SignatureVerifier.verify_document(
            document_path=self.doc_path,
            signature_source=truncated_sig_path,
            public_key_source=self.pub_key_path
        )
        self.assertFalse(res_trunc.is_valid)
        self.assertIn("Malformed signature length", res_trunc.message)

        # 2. Corrupted public key file
        corrupt_key_path = self.temp_path / "corrupt_key.pem"
        with open(corrupt_key_path, "wb") as f:
            f.write(b"NOT A REAL PEM KEY")

        res_key = SignatureVerifier.verify_document(
            document_path=self.doc_path,
            signature_source=self.sig_path,
            public_key_source=corrupt_key_path
        )
        self.assertFalse(res_key.is_valid)
        self.assertIn("Malformed or invalid public key", res_key.message)

        # 3. Missing document
        missing_doc = self.temp_path / "does_not_exist.txt"
        res_missing = SignatureVerifier.verify_document(
            document_path=missing_doc,
            signature_source=self.sig_path,
            public_key_source=self.pub_key_path
        )
        self.assertFalse(res_missing.is_valid)
        self.assertIn("does not exist", res_missing.message)

    def test_pregenerated_sample_artifacts(self):
        """Confirm that sample_data/sample_document.txt verifies with repository artifacts."""
        repo_root = Path(__file__).resolve().parent.parent
        doc_path = repo_root / "sample_data" / "sample_document.txt"
        sig_path = repo_root / "artifacts" / "sample_document.sig"
        pub_path = repo_root / "artifacts" / "signer_public_key.pem"

        self.assertTrue(doc_path.is_file(), f"Missing {doc_path}")
        self.assertTrue(sig_path.is_file(), f"Missing {sig_path}")
        self.assertTrue(pub_path.is_file(), f"Missing {pub_path}")

        result = SignatureVerifier.verify_document(doc_path, sig_path, pub_path)
        self.assertTrue(result.is_valid, f"Sample artifacts failed verification: {result.message}")

        # Validate fingerprint computation
        fingerprint = KeyFingerprint.compute_fingerprint(pub_path)
        self.assertTrue(fingerprint.startswith("SHA256:"))
        self.assertTrue(KeyFingerprint.verify_fingerprint(pub_path, fingerprint))


if __name__ == "__main__":
    unittest.main()
