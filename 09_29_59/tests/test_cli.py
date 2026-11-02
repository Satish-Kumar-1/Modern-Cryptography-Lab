"""Unit and integration tests for the CLI Application (Person 3).

Validates CLI entry points, argument parsing, workflow execution, exit codes,
and error handling.
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from src.key_fingerprint import KeyFingerprint
from src.key_manager import KeyManager
from src.main import main


class TestCLIApplication(unittest.TestCase):
    """Test suite covering python -m src.main CLI commands."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_help(self):
        """Confirm CLI --help displays usage and exits with code 0."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        output = buf.getvalue()
        self.assertIn("Ed25519-based document signing", output)
        self.assertIn("keygen", output)
        self.assertIn("verify", output)

    def test_cli_verify_default_sample_artifacts(self):
        """Confirm default verify command succeeds on repository sample artifacts."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["verify"])
        self.assertEqual(exit_code, 0)
        self.assertIn("AUTHENTIC (VALID)", buf.getvalue())

    def test_cli_verify_tampered_document(self):
        """Confirm CLI verify fails when document content has been modified."""
        repo_root = Path(__file__).resolve().parent.parent
        doc_path = repo_root / "sample_data" / "sample_document.txt"
        sig_path = repo_root / "artifacts" / "sample_document.sig"
        pub_path = repo_root / "artifacts" / "signer_public_key.pem"

        tampered_doc = self.temp_path / "tampered.txt"
        tampered_doc.write_bytes(doc_path.read_bytes() + b"\nTampered byte.")

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([
                "verify",
                "--document", str(tampered_doc),
                "--signature", str(sig_path),
                "--public-key", str(pub_path),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("NOT AUTHENTIC (INVALID)", buf.getvalue())

    def test_cli_verify_corrupted_signature(self):
        """Confirm CLI verify fails when signature bytes are corrupted."""
        repo_root = Path(__file__).resolve().parent.parent
        doc_path = repo_root / "sample_data" / "sample_document.txt"
        sig_path = repo_root / "artifacts" / "sample_document.sig"
        pub_path = repo_root / "artifacts" / "signer_public_key.pem"

        bad_sig = self.temp_path / "corrupted.sig"
        sig_bytes = bytearray(sig_path.read_bytes())
        sig_bytes[0] ^= 0xFF
        bad_sig.write_bytes(sig_bytes)

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([
                "verify",
                "--document", str(doc_path),
                "--signature", str(bad_sig),
                "--public-key", str(pub_path),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("NOT AUTHENTIC (INVALID)", buf.getvalue())

    def test_cli_verify_wrong_public_key(self):
        """Confirm CLI verify fails when an unrelated public key is provided."""
        repo_root = Path(__file__).resolve().parent.parent
        doc_path = repo_root / "sample_data" / "sample_document.txt"
        sig_path = repo_root / "artifacts" / "sample_document.sig"

        _, wrong_pub = KeyManager.generate_key_pair()
        wrong_pub_path = self.temp_path / "unrelated_pub.pem"
        KeyManager.save_public_key(wrong_pub, wrong_pub_path)

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([
                "verify",
                "--document", str(doc_path),
                "--signature", str(sig_path),
                "--public-key", str(wrong_pub_path),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("NOT AUTHENTIC (INVALID)", buf.getvalue())

    def test_cli_verify_missing_file(self):
        """Confirm CLI verify returns exit code 1 for non-existent file."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([
                "verify",
                "--document", str(self.temp_path / "missing.txt"),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("does not exist", buf.getvalue())

    def test_cli_fingerprint_computation(self):
        """Confirm CLI fingerprint displays canonical SHA-256 fingerprint."""
        repo_root = Path(__file__).resolve().parent.parent
        pub_path = repo_root / "artifacts" / "signer_public_key.pem"

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["fingerprint", "--public-key", str(pub_path)])
        self.assertEqual(exit_code, 0)
        output = buf.getvalue()
        self.assertIn("SHA256:", output)

    def test_cli_fingerprint_trust_verification(self):
        """Confirm CLI fingerprint verifies matching and detects mismatching hashes."""
        repo_root = Path(__file__).resolve().parent.parent
        pub_path = repo_root / "artifacts" / "signer_public_key.pem"
        expected_fp = KeyFingerprint.compute_fingerprint(pub_path)

        # Match check -> exits 0
        buf_match = io.StringIO()
        with redirect_stdout(buf_match):
            exit_code_match = main([
                "fingerprint",
                "--public-key", str(pub_path),
                "--expected", expected_fp,
            ])
        self.assertEqual(exit_code_match, 0)
        self.assertIn("[TRUSTED]", buf_match.getvalue())

        # Mismatch check -> exits 1
        buf_mismatch = io.StringIO()
        with redirect_stdout(buf_mismatch):
            exit_code_mismatch = main([
                "fingerprint",
                "--public-key", str(pub_path),
                "--expected", "SHA256:00:11:22:33:44:55",
            ])
        self.assertEqual(exit_code_mismatch, 1)
        self.assertIn("[UNTRUSTED]", buf_mismatch.getvalue())

    def test_cli_keygen_sign_verify_with_passphrase(self):
        """Test full CLI lifecycle with passphrase encryption."""
        priv_key_path = self.temp_path / "test_priv.pem"
        pub_key_path = self.temp_path / "test_pub.pem"
        doc_path = self.temp_path / "credential.txt"
        sig_path = self.temp_path / "credential.sig"

        doc_path.write_bytes(b"Academic Degree Certificate: Person 3 CLI Test")

        # 1. Keygen with passphrase
        buf_kg = io.StringIO()
        with redirect_stdout(buf_kg):
            exit_kg = main([
                "keygen",
                "--private-key", str(priv_key_path),
                "--public-key", str(pub_key_path),
                "--password", "StrongKeyPassword2026!",
            ])
        self.assertEqual(exit_kg, 0)
        self.assertTrue(priv_key_path.is_file())
        self.assertTrue(pub_key_path.is_file())

        # 2. Overwrite protection without --force -> fails
        buf_ov = io.StringIO()
        with redirect_stdout(buf_ov):
            exit_ov = main([
                "keygen",
                "--private-key", str(priv_key_path),
                "--public-key", str(pub_key_path),
                "--password", "AnotherPassword!",
            ])
        self.assertEqual(exit_ov, 1)
        self.assertIn("already exist", buf_ov.getvalue())

        # 3. Sign document with passphrase
        buf_sign = io.StringIO()
        with redirect_stdout(buf_sign):
            exit_sign = main([
                "sign",
                "--document", str(doc_path),
                "--private-key", str(priv_key_path),
                "--signature", str(sig_path),
                "--password", "StrongKeyPassword2026!",
            ])
        self.assertEqual(exit_sign, 0)
        self.assertTrue(sig_path.is_file())
        self.assertEqual(sig_path.stat().st_size, 64)

        # 4. Verify document
        buf_ver = io.StringIO()
        with redirect_stdout(buf_ver):
            exit_ver = main([
                "verify",
                "--document", str(doc_path),
                "--signature", str(sig_path),
                "--public-key", str(pub_key_path),
            ])
        self.assertEqual(exit_ver, 0)
        self.assertIn("AUTHENTIC (VALID)", buf_ver.getvalue())

    def test_cli_keygen_sign_verify_unencrypted(self):
        """Test CLI keygen and signing with unencrypted private key."""
        priv_key_path = self.temp_path / "unenc_priv.pem"
        pub_key_path = self.temp_path / "unenc_pub.pem"
        doc_path = self.temp_path / "unenc_doc.txt"
        sig_path = self.temp_path / "unenc_sig.sig"

        doc_path.write_bytes(b"Testing unencrypted key lifecycle.")

        # Keygen with --no-password
        buf_kg = io.StringIO()
        with redirect_stdout(buf_kg):
            exit_kg = main([
                "keygen",
                "--private-key", str(priv_key_path),
                "--public-key", str(pub_key_path),
                "--no-password",
            ])
        self.assertEqual(exit_kg, 0)

        # Sign without password
        buf_sign = io.StringIO()
        with redirect_stdout(buf_sign):
            exit_sign = main([
                "sign",
                "--document", str(doc_path),
                "--private-key", str(priv_key_path),
                "--signature", str(sig_path),
            ])
        self.assertEqual(exit_sign, 0)

        # Verify
        buf_ver = io.StringIO()
        with redirect_stdout(buf_ver):
            exit_ver = main([
                "verify",
                "--document", str(doc_path),
                "--signature", str(sig_path),
                "--public-key", str(pub_key_path),
            ])
        self.assertEqual(exit_ver, 0)

    def test_cli_all_workflow(self):
        """Confirm python -m src.main all runs all 3 phases cleanly."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["all"])
        self.assertEqual(exit_code, 0)
        output = buf.getvalue()
        self.assertIn("ALL WORKFLOW STAGES COMPLETED SUCCESSFULLY", output)
        self.assertIn("PHASE 1: Auditing Repository Submission Artifacts", output)
        self.assertIn("PHASE 2: Live End-to-End Cryptographic Lifecycle", output)
        self.assertIn("PHASE 3: Tamper Detection Demonstration", output)


if __name__ == "__main__":
    unittest.main()
